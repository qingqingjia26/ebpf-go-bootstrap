package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	th "ebpf-go-bootstrap/src/trace-helper"
)

const uint64Size int32 = 64 / 8

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event bpf snoop.c -- -I../../../src/headers

func startOpenTestBinary() int {
	filepath := "../user-prog/c/send_pkg.bin"
	cmd := exec.Command(filepath)
	err := cmd.Start()
	if err != nil {
		fmt.Printf("Error starting command: %v\n", err)
		return -1
	}

	// Wait for the process to finish or kill it after a timeout (whichever comes first)
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	return cmd.Process.Pid

}

var usyms *th.USyms = th.NewUSyms()
var ksyms *th.KSyms = th.NewKSyms()

func main() {
	pid := startOpenTestBinary()
	if pid == -1 {
		log.Fatal("failed to start open_test.bin")
	}
	log.Println("open_test.bin pid:", pid)

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

	// set pid to filter
	if err := objs.bpfMaps.PidMap.Put(uint32(0), uint32(pid)); err != nil {
		log.Fatalf("failed to put pid into map: %v", err)
	}
	// attach
	tp, err := link.Tracepoint("net", "net_dev_start_xmit", objs.NetXmit, nil)
	if err != nil {
		log.Fatalf("failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	// init ringbuf
	rb, err := ringbuf.NewReader(objs.bpfMaps.Rb)
	if err != nil {
		log.Fatalf("failed to create ringbuf reader: %v", err)
	}
	defer rb.Close()

	go func() {
		<-stopper
		// kill process
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
			log.Fatalf("failed to kill process: %v", err)
		}
		if err := rb.Close(); err != nil {
			log.Fatalf("failed to close ringbuf reader: %v", err)
		}

	}()

	if err := ksyms.KSymload(); err != nil {
		log.Fatalf("failed to load kernel symbols: %v", err)
	}
	if err := usyms.LoadPid(pid); err != nil {
		log.Fatalf("failed to load user symbols: %v", err)
	}
	// read ringbuf
	var event bpfEvent
	for {
		record, err := rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received stop signal, exiting")
				return
			}
			log.Printf("failed to read record: %s", err)
			continue
		}
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("failed to parse event: %v", err)
			continue
		}
		event.KstackSize /= uint64Size
		event.UstackSize /= uint64Size

		fmt.Println("pid", event.Pid, "tpid", event.Ppid, "kstack size:", event.KstackSize, "ustack size:", event.UstackSize)
		fmt.Println("-----")
		fmt.Println("kernel stack:")
		for i := 1; i < int(event.KstackSize) && i < len(event.Kstack); i++ {
			addr := event.Kstack[i]
			if addr == 0 {
				continue
			}
			kstr, ok := ksyms.GetSym(addr)
			if ok {
				fmt.Printf("0x%x %s\n", event.Kstack[i], kstr.Name)
			} else {
				fmt.Printf("0x%x\n", addr)
			}

		}
		fmt.Println("\n-----")
		fmt.Println("user stack:")
		for i := 0; i < int(event.UstackSize)-1 && i < len(event.Ustack); i++ {
			addr := event.Ustack[i]
			if addr == 0 {
				continue
			}
			ustr, ok := usyms.GetSym(addr)
			if ok {
				fmt.Printf("0x%x %s\n", event.Ustack[i], ustr.Name)
			} else {
				fmt.Printf("0x%x\n", event.Ustack[i])
			}
		}
		fmt.Println()
	}
}
