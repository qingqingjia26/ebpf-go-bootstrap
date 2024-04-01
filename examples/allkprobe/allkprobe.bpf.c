//go:build ignore

#include "vmlinux.h"
#include "bpf_endian.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile int32 my_pid = 0;
SEC("kprobe/any")
int all_kprobe(void *ctx)
{
	pid_t pid;
	const char *filename;

	pid = bpf_get_current_pid_tgid() >> 32;
    if(!my_pid || my_pid != pid)
        return 1;

	bpf_printk("KPROBE ENTRY pid = %d\n", pid);
	return 0;
}