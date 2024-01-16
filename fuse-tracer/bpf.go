package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -type fuse_req_evt fuse_tracer bpf.c
