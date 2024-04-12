//go:build ignore

// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Jingxiang Zeng
// Copyright (c) 2022 Krisztian Fekete
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

struct data_t {
	__u32 fpid;
	__u32 tpid;
	__u64 pages;
	char fcomm[TASK_COMM_LEN];
	char tcomm[TASK_COMM_LEN];
};

struct data_t *unused __attribute((unused));

SEC("kprobe/oom_kill_process")
int BPF_KPROBE(oom_kill_process, struct oom_control *oc, const char *message)
{
	struct data_t data = {};

	data.fpid = bpf_get_current_pid_tgid() >> 32;
	data.tpid = BPF_CORE_READ(oc, chosen, tgid);
	data.pages = BPF_CORE_READ(oc, totalpages);
	bpf_get_current_comm(&data.fcomm, sizeof(data.fcomm));
	bpf_probe_read_kernel(&data.tcomm, sizeof(data.tcomm), BPF_CORE_READ(oc, chosen, comm));
	bpf_printk("Triggered by PID %d (\"%s\"), OOM kill of PID %d (\"%s\"), %lld pages",
			data.fpid, data.fcomm, data.tpid, data.tcomm, data.pages);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
