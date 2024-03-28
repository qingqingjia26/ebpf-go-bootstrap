package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --target amd64 -type bind_event bpf bindsnoop.bpf.c -- -I../../src/headers

var emitTimestamp bool = false
var targetPid int = 0
var ignoreErrors bool = true
var targetPorts string = ""
var verbose bool = false
var cgroupspath string = ""

var logOpts = slog.HandlerOptions{
	AddSource: false,
	Level:     slog.LevelDebug,
}

func parseCmd() {
	flag.BoolVar(&emitTimestamp, "t", false, "Emit timestamp")
	flag.IntVar(&targetPid, "p", 0, "Filter by PID")
	flag.BoolVar(&ignoreErrors, "x", true, "include errors on output")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.StringVar(&cgroupspath, "c", "", "Trace process under cgroupsPath")
	flag.StringVar(&targetPorts, "P", "", "Filter by ports")

	flag.Parse()
	if verbose {
		logOpts.Level = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &logOpts)))
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

	// pid := os.Getpid()

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
