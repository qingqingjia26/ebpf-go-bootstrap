package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --target amd64 bpf ksyscall.bpf.c -- -I../../src/headers

func newAndKillProg() {
	cmd := exec.Command("/bin/sleep", "60")

	if err := cmd.Start(); err != nil {
		fmt.Printf("create process failed: %v\n", err)
		return
	}
	time.Sleep(1 * time.Second)

	// 杀死进程
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		fmt.Printf("kill process failed: %v\n", err)
		return
	}
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

	kp, err := link.Kprobe("__x64_sys_kill", objs.EntryProbe, nil)
	if err != nil {
		log.Fatalf("failed to attach kprobe: %v", err)
	}
	defer kp.Close()

	kp2, err := link.Kprobe("__x64_sys_tgkill", objs.TgkillEntry, nil)
	if err != nil {
		log.Fatalf("failed to attach kprobe: %v", err)
	}
	defer kp2.Close()
	fmt.Println("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.")
	for {
		select {
		case <-stopper:
			return
		default:
			fmt.Printf(".")
			newAndKillProg()
			time.Sleep(time.Second)
		}
	}

}
