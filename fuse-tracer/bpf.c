//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <linux/limits.h>

char LICENSE[] SEC("license") = "GPL";

#define FUSE_ARG_SZ 128

struct _fuse_arg {
    u16 size;
    u8 value[FUSE_ARG_SZ];
};

struct fuse_req_evt {
    u64 start_ktime;
    u64 end_ktime;
    struct fuse_in_header in_h;
    u64 flags;
    u64 end_flags;

    u8 in_numargs;
    struct _fuse_arg in_args[3];
    
    u8 out_numargs;
    struct _fuse_arg out_args[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct fuse_req_evt);
    __uint(max_entries, 1);
} req_heap SEC(".maps"); // We don't have a heap but we've maps

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, u32);
    __type(value, struct fuse_req_evt);
    __uint(max_entries, 1024);
} inflight_reqs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);
} fuse_req_events SEC(".maps");

static int read_fuse_in_arg(struct _fuse_arg *dst, struct fuse_args *args, int arg_id) {
    struct fuse_in_arg arg = BPF_CORE_READ(args, in_args[arg_id]);
    
    u16 arg_size = arg.size;
    if (arg_size > FUSE_ARG_SZ) {
        arg_size = FUSE_ARG_SZ;
    }
    if (arg_size <= 0) {
        return 0;
    }

    if (bpf_probe_read_kernel(&dst->value, arg_size, arg.value) < 0) {
        return -1;
    }

    // The BPF verifier rejects the program when dst->size is assigned from arg_size.
    // So we've to reimplement the same logic a second time here...
    dst->size = arg.size;
    if (dst->size > FUSE_ARG_SZ) {
        dst->size = FUSE_ARG_SZ;
    } else if (dst->size <= 0) {
        dst->size = 0;
    }

    return 0;
}

static int read_fuse_in_args(struct fuse_req_evt *evt, struct fuse_args *args) {
    evt->in_numargs = BPF_CORE_READ(args, in_numargs);

    for (int i = 0; i < 3 && i < evt->in_numargs; i++) {
        if (read_fuse_in_arg(&evt->in_args[i], args, i) < 0) {
            bpf_printk("couldn't read fuse in_arg%d", i);
            return -1;
        }
    }

    return 0;
}

static int read_fuse_out_arg(struct _fuse_arg *dst, struct fuse_args *args, int arg_id) {
    struct fuse_arg arg = BPF_CORE_READ(args, out_args[arg_id]);
    
    int arg_size = arg.size;
    if (arg_size > FUSE_ARG_SZ) {
        arg_size = FUSE_ARG_SZ;
    }
    if (arg_size <= 0) {
        return 0;
    }

    if (bpf_probe_read_kernel(&dst->value, arg_size, arg.value) < 0) {
        return -1;
    }

    // The BPF verifier rejects the program when dst->size is assigned from arg_size.
    // So we've to reimplement the same logic a second time here...
    dst->size = arg.size;
    if (dst->size > FUSE_ARG_SZ) {
        dst->size = FUSE_ARG_SZ;
    } else if (dst->size <= 0) {
        dst->size = 0;
    }

    return 0;
}

static int read_fuse_out_args(struct fuse_req_evt *evt, struct fuse_args *args) {
    evt->out_numargs = BPF_CORE_READ(args, out_numargs);

    for (int i = 0; i < 3 && i < evt->out_numargs; i++) {
        if (read_fuse_out_arg(&evt->out_args[i], args, i) < 0) {
            bpf_printk("couldn't read fuse out_arg%d", i);
            return -1;
        }
    }

    return 0;
}

// fuse_simple_request -> __fuse_request_send -> queue_request_and_unlock
// fuse_simple_background -> fuse_request_queue_background -> flush_bg_queue -> queue_request_and_unlock
// fuse_simple_notify_reply -> queue_request_and_unlock
SEC("fentry/queue_request_and_unlock")
int BPF_PROG(trace_fuse_request, struct fuse_iqueue *fiq, struct fuse_req *req) {
    if (req->args == NULL) {
        return 0;
    }

    struct fuse_args *args = BPF_CORE_READ(req, args);

    u32 map_id = 0;
    struct fuse_req_evt *evt = bpf_map_lookup_elem(&req_heap, &map_id);
    if (evt == NULL) {
        return 0;
    }

    evt->start_ktime = bpf_ktime_get_ns();
    evt->in_h = BPF_CORE_READ(req, in.h);
    evt->flags = BPF_CORE_READ(req, flags);

    if (read_fuse_in_args(evt, args) < 0) {
        return 0;
    }
    
    u64 req_id = evt->in_h.unique;
    bpf_map_update_elem(&inflight_reqs, &req_id, evt, 0);
    return 0;
}

// fuse_simple_request -> __fuse_request_send -> request_wait_answer
SEC("fentry/request_wait_answer")
int BPF_PROG(trace_request_wait_answer, struct fuse_req *req) {
    u64 req_id = BPF_CORE_READ(req, in.h.unique);
    if (req_id == 0) {
        return 0;
    }

    struct fuse_req_evt *evt = bpf_map_lookup_elem(&inflight_reqs, &req_id);
    if (evt == NULL) {
        bpf_printk("couldn't find key %d in inflight_reqs", req_id);
        return 0;
    }

    evt->end_ktime = bpf_ktime_get_ns();
    evt->end_flags = BPF_CORE_READ(req, flags);
    
    struct fuse_args *args = BPF_CORE_READ(req, args);
    if (read_fuse_out_args(evt, args) < 0) {
        return 0;
    }

    bpf_ringbuf_output(&fuse_req_events, evt, sizeof(struct fuse_req_evt), 0);

    return 0;
}

// fuse_dev_read | fuse_dev_splice_read -> fuse_dev_do_read -> fuse_request_end
// fuse_dev_write | fuse_dev_splice_write -> fuse_dev_do_write -> fuse_request_end
// end_requests -> fuse_request_end