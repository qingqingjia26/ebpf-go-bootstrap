//go:build ignore

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2023 Hosein Bakhtiari */
#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/task/task_newtask")
int handle_tp(struct trace_event_raw_task_newtask *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    u32 uid = bpf_get_current_uid_gid() >> 32;
    bpf_printk("New task created with PID %d, TID %d, UID %d comm:%s task_id:%d.\n", pid, tid, uid, ctx->comm, ctx->pid);
    return 0;
}
