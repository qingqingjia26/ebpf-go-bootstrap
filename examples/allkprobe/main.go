package main

import (
	"bufio"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  bpf allkprobe.bpf.c -- -I../../src/headers

func getAllKsym() []string {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	syms := make([]string, 0, 10000)
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		var addr uint64
		var name, typ, module string

		if len(strings.Fields(sc.Text())) == 3 {
			_, err := fmt.Sscanf(sc.Text(), "%x %s %s", &addr, &typ, &name)
			if err != nil {
				log.Fatal(err)
			}
		} else if len(strings.Fields(sc.Text())) == 4 {
			_, err := fmt.Sscanf(sc.Text(), "%x %s %s %s", &addr, &typ, &module, &name)
			if err != nil {
				log.Fatal(err)
			}
		}
		syms = append(syms, name)
	}
	if len(syms) == 0 {
		log.Fatal("no symbols found")
	}
	return syms
}

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock limit: %v", err)
	}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("loading BPF object: %s", err)
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading BPF object: %s", err)
	}

	err = spec.RewriteConstants(map[string]interface{}{
		"my_pid": int32(os.Getpid()),
	})

	err = spec.LoadAndAssign(&objs, nil)
	if err != nil {
		log.Fatalf("loading BPF object: %s", err)
	}

	allKsyms := getAllKsym()
	successCnt := 0
	failCnt := 0

	fmt.Println("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.")

	for idx, ksym := range allKsyms {
		if idx%100 == 0 {
			fmt.Println("Success count: ", successCnt, " Fail count: ", failCnt)
		}
		kp, err := link.Kprobe(ksym, objs.AllKprobe, nil)
		if err != nil {
			failCnt++
			continue
		}
		defer kp.Close()
		successCnt++
		select {
		case <-stopper:
			slog.Info("stopping allkprobe")
			return
		default:
		}
	}

}
