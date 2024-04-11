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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf newtask.bpf.c -- -I../../src/headers

func getDevIno() (uint64, uint64) {
	fileinfo, err := os.Stat("/proc/self/ns/pid")
	if err != nil {
		log.Fatalf("failed to get pid ns: %v", err)
	}
	stat, ok := fileinfo.Sys().(*syscall.Stat_t)
	if !ok {
		log.Fatalf("failed to get pid ns: %v", err)
	}
	return stat.Dev, stat.Ino
}

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

	tp, err := link.Tracepoint("task", "task_newtask", objs.HandleTp, nil)
	if err != nil {
		log.Fatalf("failed to open tracepoint: %v", err)
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
