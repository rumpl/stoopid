package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/aybabtme/uniplot/histogram"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
)

var dumpFlag = flag.Bool("dump", false, "Dump requests / replies")
var hexFlag = flag.Bool("hex", false, "Show args in hex format")
var statsFlag = flag.Bool("stats", false, "Show requests / replies stats")
var histFlag = flag.Bool("hist", false, "Show histogram of request time")
var stacktraceFlag = flag.Bool("stacktrace", false, "Dump kernel stacktraces")

type fuseOpStats struct {
	Count     int
	TotalTime uint64
}

var fuseOpsStats map[uint32]fuseOpStats
var fuseOpsHistData []float64

var progNames = []string{
	"trace_fuse_request",
	"trace_request_wait_answer",
}

func main() {
	flag.Parse()

	if !*dumpFlag && (*hexFlag || *stacktraceFlag) {
		panic("You need to specify -dump")
	}
	if !*dumpFlag && !*statsFlag && !*histFlag {
		panic("You need to specify either -dump, -stats or -hist")
	}

	logrus.SetLevel(logrus.DebugLevel)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	fuseOpsStats = make(map[uint32]fuseOpStats)
	fuseOpsHistData = []float64{}

	reader := bytes.NewReader(_Fuse_tracerBytes)
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

	for _, progName := range progNames {
		l, err := link.AttachTracing(link.TracingOptions{Program: coll.Programs[progName]})
		if err != nil {
			panic(err)
		}

		attached[progName] = l
	}

	fuseEventsReader, err := ringbuf.NewReader(coll.Maps["fuse_req_events"])
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go WatchFuseEvents(ctx, fuseEventsReader)

	<-c
	cancel()

	if *statsFlag {
		printOpsStats()
	}
	if *histFlag {
		printOpsHist()
	}

	for _, l := range attached {
		l.Close()
	}
}

func printOpsStats() {
	fmt.Print("\nStats:\n")

	totalCount := 0
	totalTime := 0

	for opcode, stat := range fuseOpsStats {
		fmt.Printf("    - %s: %d calls (total time: %.3fµs)\n", fuseOperation(opcode), stat.Count, float64(stat.TotalTime)/1e3)
		totalCount += stat.Count
		totalTime += int(stat.TotalTime)
	}

	fmt.Printf("    - Total: %d calls (total time: %.3fµs)\n", totalCount, float64(totalTime)/1e3)
}

func printOpsHist() {
	fmt.Print("\nHistogram:\n")

	hist := histogram.Hist(10, fuseOpsHistData)
	if err := histogram.Fprintf(os.Stdout, hist, histogram.Linear(5), func(v float64) string {
		return time.Duration(v).String()
	}); err != nil {
		panic(err)
	}
}

func WatchFuseEvents(ctx context.Context, fuseEventsReader *ringbuf.Reader) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		record, err := fuseEventsReader.Read()
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return nil
			}
			logrus.WithField("error", err).Error("error reading from fuse_events reader")
			continue
		}

		var fuseEvt fuse_tracerFuseReqEvt
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &fuseEvt); err != nil {
			logrus.WithField("error", err).Error("could not parse fuse_req_evt")
			continue
		}

		if *dumpFlag {
			fmt.Printf("%s\n", fuseEvent(fuseEvt))
		}

		opStat, ok := fuseOpsStats[fuseEvt.InH.Opcode]
		if !ok {
			opStat = fuseOpStats{}
		}

		opStat.Count++
		opStat.TotalTime += fuseEvt.EndKtime - fuseEvt.StartKtime
		fuseOpsStats[fuseEvt.InH.Opcode] = opStat
		fuseOpsHistData = append(fuseOpsHistData, float64(opStat.TotalTime))
	}
}

func fuseEvent(fuseEvt fuse_tracerFuseReqEvt) string {
	b := &strings.Builder{}

	fmt.Fprintf(b, "[%d] %s (Len: %d - Request ID: %d - UID: %d - GID: %d - PID: %d): took %.3fµs\n",
		fuseEvt.StartKtime,
		fuseOperation(fuseEvt.InH.Opcode),
		fuseEvt.InH.Len,
		fuseEvt.InH.Unique,
		fuseEvt.InH.Uid,
		fuseEvt.InH.Gid,
		fuseEvt.InH.Pid,
		float64(fuseEvt.EndKtime-fuseEvt.StartKtime)/1e3)

	if fuseEvt.InNumargs == 0 {
		fmt.Fprint(b, "    - (no in args)")
	}

	for i := 0; i < int(fuseEvt.InNumargs); i++ {
		arg := fuseEvt.InArgs[i]
		if *hexFlag {
			fmt.Fprintf(b, "    - In Arg %d:\n%s", i, hex.Dump(arg.Value[:arg.Size]))
		} else {
			fmt.Fprintf(b, "    - In Arg %d: %s\n", i, bytes.Trim(arg.Value[:arg.Size], "\x00"))
		}
	}

	if fuseEvt.OutNumargs == 0 {
		fmt.Fprint(b, "    - (no out args)")
	}

	for i := 0; i < int(fuseEvt.OutNumargs); i++ {
		arg := fuseEvt.OutArgs[i]
		if *hexFlag {
			fmt.Fprintf(b, "    - Out Arg %d:\n%s", i, hex.Dump(arg.Value[:arg.Size]))
		} else {
			fmt.Fprintf(b, "    - Out Arg %d: %s\n", i, bytes.Trim(arg.Value[:arg.Size], "\x00"))
		}
	}

	return b.String()
}
