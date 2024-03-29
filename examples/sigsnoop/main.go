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

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event bpf sigsnoop.bpf.c -- -I../../src/headers

var traceFail bool
var traceOnlySyscall bool
var targetPid int
var targetSigNum int

func parseCmd() {
	flag.BoolVar(&traceFail, "x", false, "Trace failed syscalls")
	flag.BoolVar(&traceOnlySyscall, "k", false, "Trace signals issued by kill syscall only.")
	flag.IntVar(&targetPid, "p", 0, "Filter by PID")
	flag.IntVar(&targetSigNum, "s", 0, "Filter by signal number")

	flag.Parse()
	slog.Info("show parameter", "traceFail", traceFail, "traceOnlySyscall", traceOnlySyscall, "targetPid", targetPid, "targetSigNum", targetSigNum)
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
		"filtered_pid":  uint32(targetPid),
		"target_signal": uint32(targetSigNum),
		"failed_only":   traceFail,
	})
	if err != nil {
		slog.Error("failed to rewrite constants", "err", err)
		return
	}
	err = spec.LoadAndAssign(&objs, nil)
	if err != nil {
		slog.Error("failed to load and assign", "err", err)
		return
	}
	if traceOnlySyscall {
		tp, err := link.Tracepoint("syscalls", "sys_exit_tgkill", objs.TgkillExit, nil)
		if err != nil {
			log.Fatalf("failed to link tracepoint: %v", err)
		}
		defer tp.Close()
		tp, err = link.Tracepoint("syscalls", "sys_exit_kill", objs.KillExit, nil)
		if err != nil {
			log.Fatalf("failed to link tracepoint: %v", err)
		}
		defer tp.Close()

		tp, err = link.Tracepoint("syscalls", "sys_exit_tkill", objs.TkillEntry, nil)
		if err != nil {
			log.Fatalf("failed to link tracepoint: %v", err)
		}
		defer tp.Close()

		tp, err = link.Tracepoint("syscalls", "sys_entry_tgkill", objs.TgkillEntry, nil)
		if err != nil {
			log.Fatalf("failed to link tracepoint: %v", err)
		}
		defer tp.Close()
		tp, err = link.Tracepoint("syscalls", "sys_entry_kill", objs.KillEntry, nil)
		if err != nil {
			log.Fatalf("failed to link tracepoint: %v", err)
		}
		defer tp.Close()

		tp, err = link.Tracepoint("syscalls", "sys_entry_tkill", objs.TkillExit, nil)
		if err != nil {
			log.Fatalf("failed to link tracepoint: %v", err)
		}
		defer tp.Close()

	} else {
		tp_enter, err := link.Tracepoint("signal", "signal_generate", objs.SigTrace, nil)
		if err != nil {
			log.Fatalf("failed to link tracepoint: %v", err)
		}
		defer tp_enter.Close()
	}

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
