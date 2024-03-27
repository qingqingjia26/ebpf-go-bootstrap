package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"ebpf-go-bootstrap/src/convert"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type task_info bpf taskiter.bpf.c -- -I../../src/headers

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

	it, err := link.AttachIter(link.IterOptions{
		Program: objs.GetTasks,
	})

	var ti bpfTaskInfo
	size := unsafe.Sizeof(ti)
	buf := make([]byte, size)
	start := 0

	file, err := it.Open()
	if err != nil {
		log.Fatalf("failed to open iter: %v", err)
	}

	for {
		select {
		case <-stopper:
			return
		default:
			n, err := file.Read(buf[start:])
			if err != nil {
				log.Fatalf("failed to read iter: %v", err)
			}
			start += n
			if start < int(size) {
				continue
			}
			start = 0
			if err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &ti); err != nil {
				log.Fatalf("failed to convert binary to struct: %v", err)
				continue
			}
			fmt.Printf("pid: %d, tid:%d comm: %s\n", ti.Pid, ti.Tid, convert.Int8Slice2String(ti.Comm[:]))
		}
	}

}
