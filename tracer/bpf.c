//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <linux/limits.h>

char LICENSE[] SEC("license") = "GPL";

#define COMM_LEN 16
#define INAME_MAX         32
#define OPER_SZ 32

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, int);
    __type(value, int);
} traced SEC(".maps");

struct file_oper {
    unsigned char oper[OPER_SZ];
    bool oper_exit;
    unsigned char comm[COMM_LEN];
    unsigned char filepath[INAME_MAX];
    unsigned long ktime;
};

// Force emitting struct file_oper into the ELF.
const struct file_oper *unused_file_oper __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024 /* 16384 KB */);
} file_opers SEC(".maps");

/* Copy up to sz - 1 bytes from zero-terminated src string and ensure that dst
 * is zero-terminated string no matter what (unless sz == 0, in which case
 * it's a no-op). It's conceptually close to FreeBSD's strlcpy(), but differs
 * in what is returned. Given this is internal helper, it's trivial to extend
 * this, when necessary. Use this instead of strncpy inside libbpf source code.
 */
static inline void libbpf_strlcpy(char *dst, const char *src, size_t sz)
{
	size_t i;

	if (sz == 0)
		return;

	sz--;
	for (i = 0; i < sz && src[i]; i++)
		dst[i] = src[i];
	dst[i] = '\0';
}

static inline int read_d_path(struct dentry *dentry, unsigned char dst[INAME_MAX]) {
    if (bpf_probe_read_kernel_str(dst, INAME_MAX, dentry->d_iname) < 0) {
        return -1;
    }

    return 0;
}

static int trace_file_oper(struct file *file, struct file_oper *evt) {
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    /* pid_t pid = BPF_CORE_READ(task, tgid);
    pid_t ppid = BPF_CORE_READ(task, parent, tgid);
    if (bpf_map_lookup_elem(&traced, &pid) == NULL) {
        return 0;
    } */

    if (bpf_get_current_comm(&evt->comm, sizeof(evt->comm)) < 0) {
        return 0;
    }

    if (bpf_strncmp(evt->comm, 3, "cat") != 0 && bpf_strncmp(evt->comm, 5, "touch") != 0) {
        return 0;
    }

    struct path fpath = BPF_CORE_READ(file, f_path);
    if (read_d_path(fpath.dentry, evt->filepath) < 0) {
        bpf_printk("couldn't read d_path");
        // return 0;
    }

    if (bpf_strncmp(evt->filepath, 5, "file_") != 0) {
        return 0;
    }

    evt->ktime = bpf_ktime_get_ns();
    bpf_ringbuf_output(&file_opers, evt, sizeof(struct file_oper), 0);

    return 0;
}

SEC("fentry/do_sys_openat2")
int BPF_PROG(trace_do_sys_openat2, int dfd, const char *filename, struct open_how *how) {
    struct file_oper evt = {
        .oper = "do_sys_openat2",
        .oper_exit = false,
        .ktime = bpf_ktime_get_ns(),
    };

    if (bpf_get_current_comm(&evt.comm, sizeof(evt.comm)) < 0) {
        return 0;
    }

    if (bpf_strncmp(evt.comm, 3, "cat") != 0 && bpf_strncmp(evt.comm, 5, "touch") != 0) {
        return 0;
    }

    if (bpf_probe_read_user_str(evt.filepath, sizeof(evt.filepath), filename) < 0) {
        bpf_printk("failed to copy filename");
        return 0;
    }

    if (bpf_strncmp(evt.filepath, 5, "file_") != 0) {
        return 0;
    }

    bpf_ringbuf_output(&file_opers, &evt, sizeof(struct file_oper), 0);
    return 0;
}

SEC("fentry/fuse_open_common")
int BPF_PROG(trace_fuse_open, struct inode *inode, struct file *file, bool isdir) {
    struct file_oper evt = {
        .oper = "fuse_open_common",
        .oper_exit = false,
    };
    trace_file_oper(file, &evt);
    return 0;
}

SEC("fentry/fuse_file_write_iter")
int BPF_PROG(trace_fuse_file_write, struct kiocb *iocb, struct iov_iter *from) {
    struct file *file = BPF_CORE_READ(iocb, ki_filp);
    struct file_oper evt = {
        .oper = "fuse_file_write_iter",
        .oper_exit = false,
    };

    trace_file_oper(file, &evt);
    return 0;
}

SEC("fentry/fuse_fsync")
int BPF_PROG(trace_fuse_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    struct file_oper evt = {
        .oper = "fuse_fsync",
        .oper_exit = false,
    };

    trace_file_oper(file, &evt);
    return 0;
}

SEC("fentry/fuse_flush")
int BPF_PROG(trace_fuse_flush, struct file *file, loff_t start, loff_t end, int datasync) {
    struct file_oper evt = {
        .oper = "fuse_flush",
        .oper_exit = false,
    };

    trace_file_oper(file, &evt);
    return 0;
}

SEC("fentry/vfs_open")
int BPF_PROG(trace_vfs_open, const struct path *path, struct file *file) {
    struct file_oper evt = {
        .oper = "vfs_open",
        .oper_exit = false,
    };

    trace_file_oper(file, &evt);
    return 0;
}

SEC("fentry/begin_new_exec")
int BPF_PROG(trace_execve, struct linux_binprm *bprm) {
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    char comm[COMM_LEN];

    if (bpf_core_read_str(comm, sizeof(comm), &task->comm) < 0) {
        return 0;
    }

    // Trace all execve made by stoopid
    if (bpf_strncmp(comm, sizeof(comm), "stoopid") != 0) {
        return 0;
    }

    pid_t tgid = BPF_CORE_READ(task, tgid);
    if (bpf_map_update_elem(&traced, &tgid, &tgid, 0) != 0) {
        bpf_printk("couldn't insert into traced map.");
    }

    return 0;
}
