//go:build ignore

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2023 Meta */
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

char LICENSE[] SEC("license") = "GPL";

#define EPERM  1

SEC("lsm/bpf")
int BPF_PROG(lsm_bpf, int cmd, union bpf_attr *attr, unsigned int size, int ret)
{
    /* ret is the return value from the previous BPF program
     * or 0 if it's the first hook.
     */
    if (ret != 0)
        return ret;

    bpf_printk("LSM: block bpf() worked");
    return -EPERM;
}
