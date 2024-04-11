package main

import (
	"bytes"
	"ebpf-go-bootstrap/src/convert"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event -type task_info bpf sigsnoop.bpf.c -- -I../../src/headers

var traceFailOnly bool
var traceOnlySyscall bool
var targetPid int
var targetSigNum int

var opts = slog.HandlerOptions{
	AddSource: false,
	Level:     slog.LevelDebug,
}

func parseCmd() {
	flag.BoolVar(&traceFailOnly, "x", false, "Trace failed syscalls")
	flag.BoolVar(&traceOnlySyscall, "k", true, "Trace signals issued by kill syscall only.")
	flag.IntVar(&targetPid, "p", 0, "Filter by PID")
	flag.IntVar(&targetSigNum, "s", 0, "Filter by signal number")

	flag.Parse()
	slog.Info("show parameter", "traceFailOnly", traceFailOnly, "traceOnlySyscall", traceOnlySyscall, "targetPid", targetPid, "targetSigNum", targetSigNum)
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &opts)))
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
		"filtered_pid":  uint32(targetPid),
		"target_signal": uint32(targetSigNum),
		"failed_only":   traceFailOnly,
	})
	if err != nil {
		slog.Error("failed to rewrite constants", "err", err)
		return
	}
	err = spec.LoadAndAssign(&objs, nil)
	if err != nil {
		slog.Error("failed to load and assign", "err", err)
		return
	}
	if traceOnlySyscall {
		tp, err := link.Tracepoint("syscalls", "sys_exit_tgkill", objs.TgkillExit, nil)
		if err != nil {
			slog.Error("failed to link tracepoint", "err", err)
		}
		defer tp.Close()
		tp, err = link.Tracepoint("syscalls", "sys_exit_kill", objs.KillExit, nil)
		if err != nil {
			slog.Error("failed to link tracepoint", "err", err)
		}
		defer tp.Close()

		tp, err = link.Tracepoint("syscalls", "sys_exit_tkill", objs.TkillExit, nil)
		if err != nil {
			slog.Error("failed to link tracepoint", "err", err)
		}
		defer tp.Close()

		tp, err = link.Tracepoint("syscalls", "sys_enter_tgkill", objs.TgkillEntry, nil)
		if err != nil {
			slog.Error("failed to link tracepoint", "err", err)
		}
		defer tp.Close()
		tp, err = link.Tracepoint("syscalls", "sys_enter_kill", objs.KillEntry, nil)
		if err != nil {
			slog.Error("failed to link tracepoint", "err", err)
		}
		defer tp.Close()

		tp, err = link.Tracepoint("syscalls", "sys_enter_tkill", objs.TkillEntry, nil)
		if err != nil {
			slog.Error("failed to link tracepoint", "err", err)
		}
		defer tp.Close()

	} else {
		tp_enter, err := link.Tracepoint("signal", "signal_generate", objs.SigTrace, nil)
		if err != nil {
			log.Fatalf("failed to link tracepoint: %v", err)
		}
		defer tp_enter.Close()
	}

	tp, err := link.Tracepoint("task", "task_newtask", objs.HandleTp, nil)
	if err != nil {
		log.Fatalf("failed to open tracepoint: %v", err)
	}
	defer tp.Close()

	pb, err := perf.NewReader(objs.Events, 64*os.Getpagesize())
	if err != nil {
		log.Fatalf("failed to create ring buffer: %v", err)
	}
	defer pb.Close()

	updateEvent, err := perf.NewReader(objs.TaskUpdateEvents, 64*os.Getpagesize())
	if err != nil {
		log.Fatalf("failed to create ring buffer: %v", err)
	}
	defer updateEvent.Close()

	// update killed process's name by /proc/pid/comm because comm is not available in task_newtask tracepoint
	go func() {
		for {
			record, err := updateEvent.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("received signal, exiting...")
					return
				}
				slog.Error("failed to read record", "err", err)
				continue
			}
			pid := uint32(0)
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &pid); err != nil {
				slog.Error("failed to decode event", "err", err)
				continue
			}
			// slog.Info("new task", "pid", pid)
			// read /proc/pid/comm and update map
			go func(pid uint32) {
				time.Sleep(time.Millisecond)
				ti := bpfTaskInfo{}
				if err := objs.Taskmap.Lookup(&pid, &ti); err != nil {
					return
				}
				comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
				if err != nil {
					return
				}
				for i := 0; i < len(comm)-1 && i < len(ti.Comm); i++ {
					ti.Comm[i] = int8(comm[i])
				}
				// fmt.Println(pid, string(comm))
				err = objs.Taskmap.Put(pid, ti)
				if err != nil {
					slog.Error("failed to update taskmap", "err", err)
				}
			}(pid)
		}
	}()

	go func() {
		<-stopper
		if err := pb.Close(); err != nil {
			log.Fatalf("failed to close ring buffer: %v", err)
		}
		if err := updateEvent.Close(); err != nil {
			log.Fatalf("failed to close ring buffer: %v", err)
		}
	}()
	var e bpfEvent
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

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			slog.Error("failed to decode event", "err", err)
			continue
		}
		// if e.Sig == 9 {
		userInfo, _ := user.LookupId(fmt.Sprintf("%d", e.Uid))

		fmt.Printf("pid: %d, tid:%d user:%s comm:%s killed_id:%d uid:%d killed_comm:%s, signal: %d\n",
			e.Pid, e.Tid, userInfo.Username, convert.Int8Slice2String(e.Comm[:]), e.KilledId, e.Uid, convert.Int8Slice2String(e.KilledComm[:]), e.Sig)
		// }
	}
}
