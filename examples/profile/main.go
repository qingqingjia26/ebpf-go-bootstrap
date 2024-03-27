package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"unsafe"

	"ebpf-go-bootstrap/src/convert"
	th "ebpf-go-bootstrap/src/trace-helper"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type stacktrace_event bpf profile.bpf.c -- -I../../src/headers

var freq uint64

func parseCmd() {
	flag.Uint64Var(&freq, "freq", 99, "sampling frequency")
	flag.Parse()
}

func main() {
	parseCmd()

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

	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_SOFTWARE,
		Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Config: uint64(unix.PERF_COUNT_HW_CPU_CYCLES),
		Sample: freq,
		Bits:   unix.PerfBitFreq,
	}
	pid := -1
	// get cpu num
	for cpu := 0; cpu < runtime.NumCPU(); cpu++ {
		fd, err := unix.PerfEventOpen(&attr, pid, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			fmt.Println("Error in perf_event_open:", err)
			return
		}
		defer unix.Close(fd)

		lk, err := link.AttachRawLink(link.RawLinkOptions{
			Program: objs.Profile,
			Target:  fd,
			Attach:  ebpf.AttachPerfEvent,
		})
		if err != nil {
			log.Fatalf("failed to attach perf event: %v", err)
		}
		defer lk.Close()
	}

	rb, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("failed to create ringbuf reader: %v", err)
	}
	defer rb.Close()

	go func() {
		<-stopper
		if err := rb.Close(); err != nil {
			log.Fatalf("failed to close ringbuf reader: %v", err)
		}
	}()

	var e bpfStacktraceEvent
	ksyms := th.NewKSyms()
	ksyms.KSymload()
	usyms := th.NewUSyms()

	for {
		record, err := rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("ringbuf closed")
				return
			}
			log.Printf("failed to read record: %v", err)
			continue
		}
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Printf("failed to read event: %v", err)
			continue
		}
		fmt.Printf("pid: %d, cpu: %d, comm: %s\n", e.Pid, e.CpuId, convert.Int8Slice2String(e.Comm[:]))
		fmt.Printf("\nkernel stack:\n")
		for i := 0; i < int(e.KstackSz/8); i++ {
			sm, ok := ksyms.GetSym(e.Kstack[i])
			if ok {
				fmt.Printf("0x%x %s\n", e.Kstack[i], sm.Name)
			} else {
				fmt.Printf("0x%x unknown\n", e.Kstack[i])
			}
		}
		fmt.Println("\nuser stack:")
		err = usyms.LoadPid(int(e.Pid))
		if err != nil {
			fmt.Printf("failed to load user symbols: %v\n", err)
			continue
		}
		for i := 0; i < int(e.UstackSz/8); i++ {
			sm, ok := usyms.GetSym(e.Ustack[i])
			if ok {
				fmt.Printf("0x%x %s\n", e.Ustack[i], sm.Name)
			} else {
				fmt.Printf("0x%x unknown\n", e.Ustack[i])
			}
		}
		fmt.Println()
	}

}
