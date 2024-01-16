FROM golang:alpine

RUN apk add --no-cache bpftool clang libbpf libbpf-dev linux-headers llvm

WORKDIR /src

COPY go.mod go.sum /src
RUN go mod download

COPY bpf.c bpf.go vmlinux.h /src
RUN go generate ./

COPY . .
RUN CGO_ENABLED=0 go build -o /usr/bin/fuse_tracer -ldflags="-extldflags=-static"

CMD ["/usr/bin/fuse_tracer", "-dump", "-hex", "-stats", "-hist"]
