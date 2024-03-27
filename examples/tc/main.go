package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf tc.bpf.c -- -I../../src/headers

const LO_IFINDEX = 1

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

	tcx, err := link.AttachTCX(link.TCXOptions{
		Interface: LO_IFINDEX,
		Program:   objs.TcIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Fatalf("failed to attach TC ingress: %v", err)
	}
	defer tcx.Close()

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
