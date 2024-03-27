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
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event bpf bootstrap.bpf.c -- -I../../src/headers

var minDurationNs uint64 = 0

func parseCmd() {
	flag.Uint64Var(&minDurationNs, "duration", 0, "Minimum process duration (ms) to report")
	flag.Parse()
}

func arrayToString(arr []int8) string {
	// 创建一个字节切片，用于保存转换后的字节
	byteArray := make([]byte, len(arr))

	// 遍历数组，将每个 int8 元素转换为对应的 ASCII 字符
	for i, v := range arr {
		byteArray[i] = byte(v)
	}

	// 将字节切片转换为字符串并返回
	return string(byteArray)
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

	tp_exit, err := link.Tracepoint("sched", "sched_process_exit", objs.HandleExit, nil)
	if err != nil {
		log.Fatalf("failed to link tracepoint: %v", err)
	}
	defer tp_exit.Close()

	tp_exec, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleExec, nil)
	if err != nil {
		log.Fatalf("failed to link tracepoint: %v", err)
	}
	defer tp_exec.Close()

	rb, err := ringbuf.NewReader(objs.Rb)
	if err != nil {
		log.Fatalf("failed to create ring buffer: %v", err)
	}
	defer rb.Close()

	go func() {
		<-stopper
		if err := rb.Close(); err != nil {
			log.Fatalf("failed to close ring buffer: %v", err)
		}
	}()
	var e bpfEvent
	for {
		record, err := rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting...")
				return
			}
			log.Printf("failed to read from ring buffer: %v", err)
			continue
		}
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Printf("failed to parse event: %v", err)
			continue
		}
		if e.ExitEvent {
			formattedTime := time.Now().Format("2006-01-02 15:04:05")
			formattedString := fmt.Sprintf("%s\t%-5s\t%-16s\t%-7d\t%-7d\t[%d]", formattedTime, "EXIT", arrayToString(e.Comm[:]), e.Pid, e.Ppid, e.ExitCode)
			fmt.Print(formattedString)
			if e.DurationNs != 0 {
				fmt.Printf(" (%d ms)", e.DurationNs/1000000)
			}
			fmt.Println()
		} else {
			formattedTime := time.Now().Format("2006-01-02 15:04:05")
			formattedString := fmt.Sprintf("%s\t%-5s\t%-16s %-7d %-7d %s\n", formattedTime, "EXEC", arrayToString(e.Comm[:]), e.Pid, e.Ppid, arrayToString(e.Filename[:]))
			fmt.Print(formattedString)
		}
	}
}
