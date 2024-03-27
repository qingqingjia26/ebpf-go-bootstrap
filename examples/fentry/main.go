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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf fentry.bpf.c -- -I../../src/headers

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

	lk, err := link.AttachTracing(link.TracingOptions{
		Program: objs.DoUnlinkat,
	})
	if err != nil {
		log.Fatalf("failed to attach tracing: %v", err)
	}
	defer lk.Close()

	lk2, err := link.AttachTracing(link.TracingOptions{
		Program: objs.DoUnlinkatExit,
	})
	if err != nil {
		log.Fatalf("failed to attach tracing: %v", err)
	}
	defer lk2.Close()

	fmt.Println("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.")
	for {
		select {
		case <-stopper:
			return
		default:
			file, _ := os.Create("example.txt")
			file.Close()
			os.Remove("example.txt")
			time.Sleep(time.Second)
		}
	}
}
