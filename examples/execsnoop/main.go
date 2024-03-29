package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event bpf execsnoop.bpf.c -- -I../../src/headers

var showTime bool
var showTimestamp bool
var showFails bool
var uid int
var cmdName string
var cmdLine string
var cgroupsPath string
var maxArgs int

var startTime time.Time

type bpfEventHdr struct {
	Pid       int32
	Ppid      int32
	Uid       uint32
	Retval    int32
	ArgsCount int32
	ArgsSize  uint32
}

func parseCmd() {
	flag.BoolVar(&showTime, "t", false, "Show time")
	flag.BoolVar(&showTimestamp, "T", false, "Show timestamp")
	flag.BoolVar(&showFails, "x", false, "Show failed execve")
	flag.IntVar(&uid, "u", -1, "Filter by UID")
	flag.StringVar(&cmdName, "n", "", "only print command where arguments equal cmdName")
	flag.StringVar(&cmdLine, "l", "", "only print command where arguments contains cmdLine")
	flag.StringVar(&cgroupsPath, "c", "", "Trace process under cgroupsPath")
	flag.IntVar(&maxArgs, "m", 20, "Maximum number of arguments to print")

	flag.Parse()
	slog.Info("show parameter", "showTime", showTime, "showTimestamp", showTimestamp, "showFails", showFails, "uid", uid, "cmdName", cmdName, "cmdLine", cmdLine, "cgroupsPath", cgroupsPath, "maxArgs", maxArgs)
}

func main() {
	parseCmd()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock limit: %v", err)
	}
	objs := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		slog.Error("failed to loadbpf", "err", err)
		return
	}
	err = spec.RewriteConstants(map[string]interface{}{
		"ignore_failed": !showFails,
		"filter_cg":     cgroupsPath != "",
		"targ_uid":      uint32(uid),
		"max_args":      uint8(maxArgs),
	})

	err = spec.LoadAndAssign(&objs, nil)
	if err != nil {
		slog.Error("failed to load and assign", "err", err)
		return
	}
	if cgroupsPath != "" {
		cgf, err := os.Open(cgroupsPath)
		if err != nil {
			slog.Error("failed to open cgroupsPath", "err", err)
			return
		}
		cgfd := cgf.Fd()
		var idx uint32 = 0
		if err := objs.CgroupMap.Put(&idx, &cgfd); err != nil {
			slog.Error("failed to put cgroup fd", "err", err)
			return
		}
	}

	startTime = time.Now()

	tp_enter, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TracepointSyscallsSysEnterExecve, nil)
	if err != nil {
		log.Fatalf("failed to link tracepoint: %v", err)
	}
	defer tp_enter.Close()

	tp_exit, err := link.Tracepoint("syscalls", "sys_exit_execve", objs.TracepointSyscallsSysExitExecve, nil)
	if err != nil {
		log.Fatalf("failed to link tracepoint: %v", err)
	}
	defer tp_exit.Close()

	pb, err := perf.NewReader(objs.Events, 64*os.Getpagesize())
	if err != nil {
		log.Fatalf("failed to create ring buffer: %v", err)
	}
	defer pb.Close()

	go func() {
		<-stopper
		if err := pb.Close(); err != nil {
			log.Fatalf("failed to close ring buffer: %v", err)
		}
	}()

	for {
		record, err := pb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting...")
				return
			}
			slog.Error("failed to read record", "err", err)
			continue
		}

		hdr := bpfEventHdr{}
		hdrSize := unsafe.Sizeof(hdr)
		if err := binary.Read(bytes.NewBuffer(record.RawSample[:hdrSize]), binary.LittleEndian, &hdr); err != nil {
			slog.Error("failed to decode event", "err", err)
			continue
		}
		resArr := bytes.Split(record.RawSample[hdrSize:], []byte{0})
		fmt.Println(hdr, len(resArr))
		for _, res := range resArr {
			fmt.Printf("%s ", string(res))
		}
		fmt.Println()
	}
}
