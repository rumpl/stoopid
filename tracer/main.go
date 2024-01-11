package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
)

func main() {
	logrus.SetLevel(logrus.DebugLevel)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	reader := bytes.NewReader(_Debug_virtiofsBytes)
	collSpec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		panic(fmt.Errorf("could not load collection spec: %w", err))
	}

	// Load eBPF programs and maps into the kernel.
	coll, err := ebpf.NewCollectionWithOptions(collSpec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	})
	if err != nil {
		panic(fmt.Errorf("could not load BPF objects from collection spec: %w", err))
	}

	attached := make(map[string]link.Link)

	for _, progName := range []string{
		"trace_fuse_open",
		"trace_fuse_file_write",
		"trace_fuse_fsync",
		"trace_fuse_flush",
		"trace_vfs_open",
		"trace_do_sys_openat2",
		"trace_execve",
	} {
		l, err := link.AttachTracing(link.TracingOptions{Program: coll.Programs[progName]})
		if err != nil {
			panic(err)
		}

		attached[progName] = l
	}

	fileOpersReader, err := ringbuf.NewReader(coll.Maps["file_opers"])
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go WatchFileOpers(ctx, fileOpersReader)

	<-c
	cancel()
}

// WatchTraceEvents reads and logs trace events from the trace_events ringbuffer
// until its reader is closed (by calling Dataplane.Close()).
func WatchFileOpers(ctx context.Context, fileOpersReader *ringbuf.Reader) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		record, err := fileOpersReader.Read()
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return nil
			}
			logrus.WithField("error", err).Error("error reading from trace_events reader")
			continue
		}

		var fileOper debug_virtiofsFileOper
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &fileOper); err != nil {
			logrus.WithField("error", err).Error("could not parse fuse_oper")
			continue
		}

		fmt.Printf("%s (%d): %s - %s\n",
			bytes.Trim(fileOper.Comm[:], "\x00"),
			fileOper.Ktime,
			operName(fileOper),
			bytes.Trim(fileOper.Filepath[:], "\x00"))
	}
}

func operName(oper debug_virtiofsFileOper) string {
	if oper.OperExit {
		return fmt.Sprintf("%s (exit)", oper.Oper)
	}
	return string(bytes.Trim(oper.Oper[:], "\x00"))
}
