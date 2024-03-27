//go:build ignore

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2023 Hosein Bakhtiari */
#include "vmlinux.h"
#include "bpf_tracing.h"



char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, u32);
	__type(value, u64);
} param_map SEC(".maps");


SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
	struct bpf_pidns_info ns;
	u32 index = 0;

	pid_t *my_pid = bpf_map_lookup_elem(&param_map, &index);
	if (!my_pid)
		return 1;

	index = 1;
	u64 *dev = bpf_map_lookup_elem(&param_map, &index);
	if(!dev)
		return 1;
	index = 2;
	u64 *ino = bpf_map_lookup_elem(&param_map, &index);
	if(!ino)
		return 1;
	bpf_get_ns_current_pid_tgid(*dev, *ino, &ns, sizeof(ns));
	if (ns.tgid != *my_pid)
		return 0;

	bpf_printk("BPF triggered from PID %d.\n", ns.pid);

	return 0;
}
