.PHONY: generate
generate:
	go generate ./

.PHONY: build
build: generate
	CGO_ENABLED=0 go build -o build/debug_virtiofs -ldflags="-extldflags=-static"

.PHONY: bpftool
bpftool:
	docker build -t bpftool -f Dockerfile.bpftool .

.PHONY: copy-into-dd
copy-into-dd:
	docker run --rm -it -v debug_virtiofs:/debug_virtiofs -v ./build:/copy -w /copy busybox /bin/sh -c "rm /debug_virtiofs/*; cp -r . /debug_virtiofs; ls -lah /debug_virtiofs"

.PHONY: run
run: build copy-into-dd
	docker run --privileged --pid=host --rm -it justincormack/nsenter1 /bin/sh -c "cd /var/lib/docker/volumes/debug_virtiofs/_data; ./debug_virtiofs"

.PHONY: dd-shell
dd-shell:
	docker run --privileged --pid=host --rm -it justincormack/nsenter1
