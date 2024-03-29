package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event bpf exitsnoop.bpf.c -- -I../../src/headers

var showFails bool
var cgroupsPath string
var targetPid int
var onlyThread bool

var startTime time.Time

type bpfEventHdr struct {
	Pid       int32
	Ppid      int32
	Uid       uint32
	Retval    int32
	ArgsCount int32
	ArgsSize  uint32
}

func parseCmd() {
	flag.BoolVar(&showFails, "x", false, "Show failed execve")
	flag.IntVar(&targetPid, "p", 0, "Filter by PID")
	flag.StringVar(&cgroupsPath, "c", "", "Trace process under cgroupsPath")
	flag.BoolVar(&onlyThread, "t", false, "Only trace thread")

	flag.Parse()
	slog.Info("show parameter", "showFails", showFails, "targetPid", targetPid, "cgroupsPath", cgroupsPath, "onlyThread", onlyThread)
}

func main() {
	parseCmd()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock limit: %v", err)
	}
	objs := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		slog.Error("failed to loadbpf", "err", err)
		return
	}
	err = spec.RewriteConstants(map[string]interface{}{
		"ignore_failed":    !showFails,
		"filter_cg":        cgroupsPath != "",
		"target_pid":       uint32(targetPid),
		"trace_by_process": onlyThread,
	})

	err = spec.LoadAndAssign(&objs, nil)
	if err != nil {
		slog.Error("failed to load and assign", "err", err)
		return
	}
	if cgroupsPath != "" {
		cgf, err := os.Open(cgroupsPath)
		if err != nil {
			slog.Error("failed to open cgroupsPath", "err", err)
			return
		}
		cgfd := cgf.Fd()
		var idx uint32 = 0
		if err := objs.CgroupMap.Put(&idx, &cgfd); err != nil {
			slog.Error("failed to put cgroup fd", "err", err)
			return
		}
	}

	startTime = time.Now()

	tp_enter, err := link.Tracepoint("sched", "sched_process_exit", objs.SchedProcessExit, nil)
	if err != nil {
		log.Fatalf("failed to link tracepoint: %v", err)
	}
	defer tp_enter.Close()

	pb, err := perf.NewReader(objs.Events, 64*os.Getpagesize())
	if err != nil {
		log.Fatalf("failed to create ring buffer: %v", err)
	}
	defer pb.Close()

	go func() {
		<-stopper
		if err := pb.Close(); err != nil {
			log.Fatalf("failed to close ring buffer: %v", err)
		}
	}()
	var e bpfEvent
	for {
		record, err := pb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting...")
				return
			}
			slog.Error("failed to read record", "err", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			slog.Error("failed to decode event", "err", err)
			continue
		}
		fmt.Println(e)
	}
}
