## load
sudo mkdir -p /sys/fs/bpf/pin-maps-dir
sudo bpftool prog load bpf_bpfel.o /sys/fs/bpf/pin-maps-prog pinmaps /sys/fs/bpf/pin-maps-dir

## attach 
sudo bpftool net attach xdp pinned /sys/fs/bpf/pin-maps-prog dev lo

## detach
sudo bpftool net detach xdp dev lo

## unload
sudo rm /sys/fs/bpf/pin-maps-dir -rf
sudo rm /sys/fs/bpf/pin-maps-prog