package main

import (
	"fmt"
	"log"
	"runtime"
	"time"

	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type datarec bpf pin_map_kern.c -- -I../../src/headers

func main() {
	pinMapPath := "/sys/fs/bpf/pin-maps-dir/xdp_stats_map"
	pm, err := ebpf.LoadPinnedMap(pinMapPath, nil)
	if err != nil {
		log.Fatalf("loading pinned map: %s", err)
	}

	numcpu := runtime.NumCPU()
	values := make([]bpfDatarec, numcpu)
	for i := 0; i < 10; i++ {
		for key := uint32(0); key < uint32(5); key++ {
			err := pm.Lookup(key, &values)
			if err != nil {
				log.Fatalf("lookup failed: %s", err)
			}
			fmt.Printf("numcpu:%d key: %d, value: %v\n", numcpu, key, values[:numcpu])
		}
		time.Sleep(1 * time.Second)
	}
}
