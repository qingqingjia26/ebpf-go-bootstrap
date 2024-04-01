package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --target amd64 -type bind_event bpf bindsnoop.bpf.c -- -I../../src/headers

var emitTimestamp bool = false
var targetPid int = 0
var ignoreErrors bool = false
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
	flag.BoolVar(&ignoreErrors, "x", false, "include errors on output")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.StringVar(&cgroupspath, "c", "", "Trace process under cgroupsPath")
	flag.StringVar(&targetPorts, "P", "", "Filter by ports")

	flag.Parse()
	if verbose {
		logOpts.Level = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &logOpts)))
	slog.Info("parameter", "emitTimestamp", emitTimestamp, "targetPid", targetPid, "ignoreErrors", ignoreErrors, "targetPorts", targetPorts, "verbose", verbose, "cgroupspath", cgroupspath)
}

func createLink(objs *bpfObjects) ([]link.Link, error) {
	linkArr := make([]link.Link, 0)
	lk, err := link.Kprobe("inet_bind", objs.Ipv4BindEntry, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create kprobe link: %v", err)
	}
	linkArr = append(linkArr, lk)

	lk, err = link.Kprobe("inet6_bind", objs.Ipv6BindEntry, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create kprobe link: %v", err)
	}
	linkArr = append(linkArr, lk)

	lk, err = link.Kprobe("inet_bind", objs.Ipv4BindExit, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create kprobe link: %v", err)
	}
	linkArr = append(linkArr, lk)

	lk, err = link.Kprobe("inet6_bind", objs.Ipv6BindExit, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create kprobe link: %v", err)
	}
	linkArr = append(linkArr, lk)
	return linkArr, nil
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
		log.Fatalf("failed to load BPF object: %v", err)
	}
	if err := spec.RewriteConstants(map[string]interface{}{
		"filter_cg":      cgroupspath != "",
		"target_pid":     int32(targetPid),
		"ignore_errors":  ignoreErrors,
		"filter_by_port": targetPorts != "",
	}); err != nil {
		log.Fatalf("failed to rewrite constants: %v", err)
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("failed to load BPF object: %v", err)
	}

	if cgroupspath != "" {
		cgfile, err := os.Open(cgroupspath)
		if err != nil {
			log.Fatalf("failed to open cgroup file: %v", err)
		}
		defer cgfile.Close()

		if err := objs.CgroupMap.Put(uint32(0), uint32(cgfile.Fd())); err != nil {
			log.Fatalf("failed to put cgroup file descriptor: %v", err)
		}
	}

	if targetPorts != "" {
		ports := strings.Split(targetPorts, ",")
		for _, port := range ports {
			portInt, err := strconv.Atoi(port)
			if err != nil {
				log.Fatalf("failed to convert port to int: %v", err)
			}
			if err := objs.Ports.Put(uint32(0), uint32(portInt)); err != nil {
				log.Fatalf("failed to put port: %v", err)
			}
		}
	}
	linkArr, err := createLink(&objs)
	if err != nil {
		log.Fatalf("failed to create link: %v", err)
	}
	for _, lk := range linkArr {
		defer lk.Close()
	}

	pb, err := perf.NewReader(objs.Events, 4096)
	if err != nil {
		log.Fatalf("failed to create perf reader: %v", err)
	}
	defer pb.Close()

	go func() {
		<-stopper
		if err := pb.Close(); err != nil {
			log.Fatalf("failed to close perf buffer: %v", err)
		}
	}()

	go func() {
		for {
			listener, err := net.Listen("tcp", ":8081")
			if err != nil {
				fmt.Println("error in listening")
			}
			time.Sleep(time.Second)
			listener.Close()
		}
	}()
	var e bpfBindEvent
	for {
		record, err := pb.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				slog.Info("perf buffer closed")
				return
			}
			slog.Error("failed to read record", "error", err)
			continue
		}
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
			slog.Error("failed to read event", "error", err)
			continue
		}
		fmt.Println(e)
	}
}
