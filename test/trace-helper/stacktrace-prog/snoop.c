//go:build ignore

#include "vmlinux.h"
#include "bpf_tracing.h"


char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_STACK_DEPTH 30

struct event {
	u32 pid;
	u32 ppid;
	int kstack_size;
	int ustack_size;
	u64 kstack[MAX_STACK_DEPTH];
	u64 ustack[MAX_STACK_DEPTH];
};

struct event *unused __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} pid_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} rb SEC(".maps");

int trace(struct trace_event_raw_net_dev_start_xmit *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	u32 tgid = pid >> 32;
	u32 zero = 0;
	u32 *val;
    struct event *evt = NULL;

	val = bpf_map_lookup_elem(&pid_map, &zero);
	if (!val) {
		return 0;
	}
	bpf_printk("pid:%d tgid:%d val:%d\n", pid, tgid, *val);
	if (*val != tgid) {
		return 0;
	}
    evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
    if(!evt) {
        return 0;
    }
	evt->pid = tgid;
	evt->ppid = bpf_get_current_pid_tgid() >> 32;
	evt->kstack_size = bpf_get_stack(ctx, evt->kstack, sizeof(evt->kstack), 0);
	evt->ustack_size = bpf_get_stack(ctx, evt->ustack, sizeof(evt->ustack), BPF_F_USER_STACK);
	bpf_ringbuf_submit(evt, 0);

	return 0;
}

SEC("tracepoint/net/net_dev_start_xmit")
int net_xmit(struct trace_event_raw_net_dev_start_xmit *ctx)
{
	return trace(ctx);
}
