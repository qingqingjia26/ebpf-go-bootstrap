# ebpf-go-bootstrap

The collection of examples for developing applications using [ebpf-go], similar to [libbpf-bootstrap], [libbpf-tools of bcc] and [xdp-tutorial]

# Requirements
A version of Go that is supported by upstream

Linux >= 4.9. CI is run against kernel.org LTS releases. 4.4 should work but is not tested against.
bpftool used to generate vmlinux.h

# Geting Started
Please take a look at [ebpf-go Getting Started] guide.

## Preparation
cd src/headers && ./get_vmlinux_header.sh  && cd -   # to get vmlinux.h headers for ebpf code

## Start
cd examples/${The program you are interested in}/

go generate . && go build . && sudo ./${The program you are interested in}

# TODO List
- [x] Verify that the trace helper module is correct
## libbpf-bootstrap
- [x] Add minimal, minimal_ns, minimal_Legacy (libbpf-bootstrap).
- [x] Add bootstrap (libbpf-bootstrap)
- [ ] Add uprobe (libbpf-bootstrap).　**Task cancelled** *because ebpf-go lacks an equivalent Uprobe feature found in libbpf-bootstrap. Nevertheless, similar functionality can be achieved with link.OpenExecutable and Executable.Uprobe as demonstrated in the uretprobe example of the ebpf-go library*
- [ ] Add usdt (libbpf-bootstrap). 　**Task cancelled** *as ebpf-go currently doesn't support USDT. A list of all supported eBPF program types can be found at https://ebpf-go.dev/concepts/section-naming/#program-sections*
- [x] Add fentry (libbpf-bootstrap)
- [x] Add kprobe (libbpf-bootstrap)
- [x] Add tc (libbpf-bootstrap)
- [x] Add profile (libbpf-bootstrap)
- [x] Add sockfilter (libbpf-bootstrap)
- [x] Add task_iter (libbpf-bootstrap)
- [x] Add lsm (libbpf-bootstrap)
- [x] Add ksyscall (libbpf-bootstrap)
## libbpf-tools of bcc
- [x] Add bindsnoop  (libbpf-tools of bcc)
- [x] Add execsnoop (libbpf-tools of bcc)
- [x] Add exitsnoop (libbpf-tools of bcc)
- [x] Add sigsnoop (libbpf-tools of bcc).  Print signal information along with the name of the process that invoked the kill
- [x] Add oomkill (libbpf-tools of bcc)

## xdp-tutorial
- [ ] Add packet parsing same as packet01-parsing
- [ ] Add packet rewriting same as packet01-rewriting
- [ ] Add packet redirecting same as packet01-redirecting
- [ ] Add tracing tcpdump same as tracing04-xdp-tcpdump
## test
- [x] Add all-kprobe
- [ ] Add pinned map

## my interest
- [x] new task snoop.   (The task_newtask function is called by all new processes or threads)
- [x] Print the killed process name.  (Implemented in the sigsnoop examples)
- [x] exit task snoop.   (All processes or threads will die call do_exit function)
- [ ] Add percpu array map example

[ebpf-go Getting Started]: https://ebpf-go.dev/guides/getting-started/
[ebpf-go]: https://github.com/cilium/ebpf
[libbpf-bootstrap]: https://github.com/libbpf/libbpf-bootstrap
[libbpf-tools of bcc]: https://github.com/iovisor/bcc/tree/master/libbpf-tools
[xdp-tutorial]: https://github.com/xdp-project/xdp-tutorial
