//go:build ignore

// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Jingxiang Zeng
// Copyright (c) 2022 Krisztian Fekete
#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_core_read.h>
#include <bpf_tracing.h>

#define TASK_COMM_LEN 16

SEC("kprobe/do_exit")
int do_exit(void *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid, tid;
	char comm[TASK_COMM_LEN];

	pid = pid_tgid >> 32;
	tid = pid_tgid;
	bpf_get_current_comm(&comm, TASK_COMM_LEN);
	bpf_printk("do exit pid =%d tid=%d, comm=%s", pid, tid, comm);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
