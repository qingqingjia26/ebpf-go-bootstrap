# ebpf-go-bootstrap

The collection of examples for developing applications using [ebpf-go], similar to [libbpf-bootstrap] and [libbpf-tools of bcc]

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
- [ ] Add bindsnoop  (libbpf-tools of bcc)
- [ ] Add cpudist (libbpf-tools of bcc)
- [ ] Add cpufreq (libbpf-tools of bcc)
- [x] Add execsnoop (libbpf-tools of bcc)
- [x] Add exitsnoop (libbpf-tools of bcc)
- [ ] Add ksnoop (libbpf-tools of bcc)
- [x] Add sigsnoop (libbpf-tools of bcc)

## test
- [x] Add all-kprobe

[ebpf-go Getting Started]: https://ebpf-go.dev/guides/getting-started/
[ebpf-go]: https://github.com/cilium/ebpf
[libbpf-bootstrap]: https://github.com/libbpf/libbpf-bootstrap
[libbpf-tools of bcc]: https://github.com/iovisor/bcc/tree/master/libbpf-tools
