package main

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf minimal.bpf.c -- -I../../src/headers

func main() {

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock limit: %v", err)
	}
	objs := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		slog.Error("failed to loadbpf", "err", err)
	}
	err = spec.RewriteConstants(map[string]interface{}{
		"my_pid": uint32(os.Getpid()),
	})
	if err != nil {
		slog.Error("failed to rewrite constants", "err", err)
		return
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		slog.Error("failed to load and assign", "err", err)
		return
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_write", objs.HandleTp, nil)
	if err != nil {
		slog.Error("failed to attach tracepoint", "err", err)
		return
	}
	defer tp.Close()

	fmt.Println("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.")
	for {
		select {
		case <-stopper:
			return
		default:
			fmt.Print(".")
			time.Sleep(time.Second)
		}
	}
}
