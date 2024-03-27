package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf minimal_legacy.bpf.c -- -I../../src/headers

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock limit: %v", err)
	}
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	pid := os.Getpid()
	// set pid to filter
	if err := objs.bpfMaps.PidMap.Put(uint32(0), uint32(pid)); err != nil {
		log.Fatalf("failed to put pid into map: %v", err)
	}
	tp, err := link.Tracepoint("syscalls", "sys_enter_write", objs.HandleTp, nil)
	if err != nil {
		log.Fatalf("failed to link tracepoint: %v", err)
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
