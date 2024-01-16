.PHONY: generate
generate:
	go generate ./

.PHONY: build
build: generate
	docker build -t albinkerouanton006/fuse-tracer .

.PHONY: run
run: build
	docker run --rm -it --privileged albinkerouanton006/fuse-tracer

vmlinux.h:
	# This is going to dump both vmlinux and fuse BTFs
	sudo bpftool btf dump id 51 format c > vmlinux.h
