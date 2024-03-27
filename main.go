package main

import (
	th "ebpf-go-bootstrap/src/trace-helper"
	"fmt"
)

func main() {
	fmt.Println("Hello, World!")
	ks := th.NewKSyms()
	fmt.Println(ks)
}
