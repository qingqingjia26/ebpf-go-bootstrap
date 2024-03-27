//go:build ignore

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2023 Hosein Bakhtiari */
#include "vmlinux.h"
#include "bpf_tracing.h"

typedef unsigned int u32;
typedef int pid_t;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Create an array with 1 entry instead of a global variable
 * which does not work with older kernels */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, pid_t);
} pid_map SEC(".maps");

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
	u32 index = 0;
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	pid_t *my_pid = bpf_map_lookup_elem(&pid_map, &index);

	if (!my_pid || *my_pid != pid)
		return 1;

	bpf_printk("BPF triggered from PID %d.", pid);

	return 0;
}
