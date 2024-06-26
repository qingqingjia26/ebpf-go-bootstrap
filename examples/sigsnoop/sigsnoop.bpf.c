//go:build ignore

// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021~2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf_helpers.h>
#include "bpf_core_read.h"

#define TASK_COMM_LEN	16

struct event {
	__u32 pid;
	__u32 tid;
	__u32 killed_id;
	__u32 uid;
	__u32 gid;
	int sig;
	int ret;
	char comm[TASK_COMM_LEN];
	char killed_comm[TASK_COMM_LEN];
};

struct event *unused __attribute__((unused));

struct task_info {
	__u32 uid;
	char comm[TASK_COMM_LEN];
};

struct task_info *unused2 __attribute__((unused));


#define MAX_ENTRIES	10240

const volatile u32 filtered_pid = 0;
const volatile u32 target_signal = 0;
const volatile bool failed_only = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct task_info);
} taskmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} task_update_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct event);
} values SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

static int probe_entry(pid_t killed_id, int sig)
{
	struct event event = {};
	__u64 pid_tgid;
	__u32 pid,tid;

	if (target_signal && sig != target_signal)
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	tid = (__u32)pid_tgid;
	if (filtered_pid && pid >> pid != filtered_pid)
		return 0;
	// if(sig == 9) {
	// bpf_printk("pid:%d, tid:%d, killed_id:%d, sig:%d\n", pid, tid, killed_id, sig);
	// }
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u32 uid = uid_gid;
	__u32 gid = uid_gid >> 32;

	event.pid = pid;
	event.tid = tid;
	event.killed_id = killed_id;
	event.sig = sig;
	event.uid = uid;
	event.gid = gid;
	bpf_get_current_comm(event.comm, sizeof(event.comm));
	bpf_map_update_elem(&values, &tid, &event, BPF_ANY);
	return 0;
}

static int probe_exit(void *ctx, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)pid_tgid;
	struct task_info *tip = NULL;
	struct event *eventp;

	eventp = bpf_map_lookup_elem(&values, &tid);
	if (!eventp)
		return 0;

	if (failed_only && ret >= 0)
		goto cleanup;
	tip = bpf_map_lookup_elem(&taskmap, &eventp->killed_id);
	if (tip) {
		for(int i=0;i<TASK_COMM_LEN;i++) {
			eventp->killed_comm[i] = tip->comm[i];
		}
	}
	eventp->ret = ret;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, eventp, sizeof(*eventp));

cleanup:
	bpf_map_delete_elem(&values, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int kill_entry(struct trace_event_raw_sys_enter *ctx)
{
	pid_t tpid = (pid_t)ctx->args[0];
	int sig = (int)ctx->args[1];

	return probe_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_kill")
int kill_exit(struct trace_event_raw_sys_exit *ctx)
{
	return probe_exit(ctx, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_tkill")
int tkill_entry(struct trace_event_raw_sys_enter *ctx)
{
	pid_t tpid = (pid_t)ctx->args[0];
	int sig = (int)ctx->args[1];

	return probe_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_tkill")
int tkill_exit(struct trace_event_raw_sys_exit *ctx)
{
	return probe_exit(ctx, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_tgkill")
int tgkill_entry(struct trace_event_raw_sys_enter *ctx)
{
	pid_t tpid = (pid_t)ctx->args[1];
	int sig = (int)ctx->args[2];

	return probe_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_tgkill")
int tgkill_exit(struct trace_event_raw_sys_exit *ctx)
{
	return probe_exit(ctx, ctx->ret);
}

SEC("tracepoint/signal/signal_generate")
int sig_trace(struct trace_event_raw_signal_generate *ctx)
{
	struct event event = {};
	pid_t tpid = ctx->pid;
	int ret = ctx->errno;
	int sig = ctx->sig;
	__u64 pid_tgid;
	__u32 pid;
	struct task_info *tip = NULL;

	if (failed_only && ret == 0)
		return 0;

	if (target_signal && sig != target_signal)
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	if (filtered_pid && pid != filtered_pid)
		return 0;

	tip = bpf_map_lookup_elem(&taskmap, &pid);
	if (tip) {
		for(int i=0;i<TASK_COMM_LEN;i++) {
			event.killed_comm[i] = tip->comm[i];
		}
	}

	event.pid = pid;
	event.killed_id = tpid;
	event.sig = sig;
	event.ret = ret;
	bpf_get_current_comm(event.comm, sizeof(event.comm));

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

SEC("tp/task/task_newtask")
int handle_tp(struct trace_event_raw_task_newtask *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = ctx->pid;
    u32 uid = bpf_get_current_uid_gid() >> 32;
	struct task_info ti = {
		.uid = uid,
	};

	bpf_core_read_str(&ti.comm, TASK_COMM_LEN, &ctx->comm);
	bpf_map_update_elem(&taskmap, &pid, &ti, BPF_ANY);

	bpf_perf_event_output(ctx, &task_update_events, BPF_F_CURRENT_CPU, &pid, sizeof(pid));
	
    // bpf_printk("New task created with PID %d, UID %d comm:%s ti.comm:%s task_id:%d.\n", pid, uid, ctx->comm,ti.comm, ctx->pid);
    return 0;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";
