package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -type file_oper debug_virtiofs bpf.c
