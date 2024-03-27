package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  bpf lsm.bpf.c -- -I../../src/headers

func lsmBpfCheck() bool {
	f, err := os.Open("/sys/kernel/security/lsm")
	if err != nil {
		log.Fatalf("failed to open lsm: %v", err)
	}
	defer f.Close()

	buf, err := io.ReadAll(f)
	if err != nil {
		log.Fatalf("failed to read lsm: %v", err)

	}
	return bytes.Contains(buf, []byte("bpf"))
}

func main() {
	if !lsmBpfCheck() {
		log.Fatalf("LSM BPF not supported on this system")
	}
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

	lsm, err := link.AttachLSM(link.LSMOptions{
		Program: objs.LsmBpf,
	})
	if err != nil {
		log.Fatalf("failed to attach lsm: %v", err)
	}
	defer lsm.Close()

	for {
		select {
		case <-stopper:
			return
		default:
			fmt.Printf(".")
			time.Sleep(time.Second)
		}
	}

}
