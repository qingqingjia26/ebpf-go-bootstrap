//go:build ignore

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2023 Meta */
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

#define TASK_COMM_LEN 16

SEC("tp/syscalls/sys_enter_tgkill")
int tgkill_entry(struct trace_event_raw_sys_enter *ctx)
{
	char comm[TASK_COMM_LEN];
	__u32 caller_pid = bpf_get_current_pid_tgid() >> 32;
	int sig =(int)ctx->args[2];
	if (sig == 0) {
		/*
			If sig is 0, then no signal is sent, but existence and permission
			checks are still performed; this can be used to check for the
			existence of a process ID or process group ID that the caller is
			permitted to signal.
		*/
		return 0;
	}

	bpf_get_current_comm(&comm, sizeof(comm));
	bpf_printk(
		"tgkill syscall called by PID %d (%s) for thread id %d with pid %d and signal %d.",
		caller_pid, comm, (pid_t)ctx->args[0],(pid_t)ctx->args[1], sig);
	return 0;
}

SEC("tp/syscalls/sys_enter_kill")
int kill_entry(struct trace_event_raw_sys_enter *ctx)
{
	char comm[TASK_COMM_LEN];
	__u32 caller_pid = bpf_get_current_pid_tgid() >> 32;
	int sig =(int)ctx->args[1];
	if (sig == 0) {
		/*
			If sig is 0, then no signal is sent, but existence and permission
			checks are still performed; this can be used to check for the
			existence of a process ID or process group ID that the caller is
			permitted to signal.
		*/
		return 0;
	}

	bpf_get_current_comm(&comm, sizeof(comm));
	bpf_printk("KILL syscall called by PID %d (%s) for PID %d with signal %d.", caller_pid,
		   comm, (pid_t)ctx->args[0], sig);
	return 0;
}

char _license[] SEC("license") = "GPL";
