package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type so_event bpf sockfilter.bpf.c -- -I../../src/headers

var ifaceName string = "lo"

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}
func parseCmd() {
	flag.StringVar(&ifaceName, "duration", "lo", "Minimum process duration (ms) to report")
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

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("failed to get interface:%v", err)
	}
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		log.Fatalf("failed to create socket:%v", err)
	}

	addr := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(sock, &addr); err != nil {
		log.Fatalf("failed to bind socket:%v", err)
	}

	err = unix.SetsockoptInt(int(sock), unix.SOL_SOCKET, unix.SO_ATTACH_BPF, objs.SocketHandler.FD())
	if err != nil {
		log.Fatalf("failed to attach BPF to socket:%v", err)
	}

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
	var e bpfSoEvent
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
		srcip := net.IPv4(byte(e.SrcAddr), byte(e.SrcAddr>>8), byte(e.SrcAddr>>16), byte(e.SrcAddr>>24))
		dstip := net.IPv4(byte(e.DstAddr), byte(e.DstAddr>>8), byte(e.DstAddr>>16), byte(e.DstAddr>>24))
		srcPort := htons(uint16(e.Ports >> 16))
		dstPort := htons(uint16(e.Ports & 0xffff))
		fmt.Printf("src:%s:%d dst:%s:%d pid:%d\n", srcip.String(), srcPort, dstip.String(), dstPort, e.IpProto)
	}
}
