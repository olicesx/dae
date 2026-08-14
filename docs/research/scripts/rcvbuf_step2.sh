#!/bin/bash
# rcvbuf step 2 (attribution): code-only SetReadBuffer(8MiB), sysctl DEFAULT.
# If loss stays ~0% -> dae ingress listener is the fix point (correct).
# If loss returns ~31% -> fix point elsewhere (server side etc).
set +e
export GOPROXY=https://goproxy.cn,direct
export GOTOOLCHAIN=auto
SRC=/mnt/c/Users/37112/Desktop/code/daes
WS=/root/daes_bench/rcvbuf
OUT=/tmp/rcvbuf_step2.log
: > "$OUT"

# force default sysctls (in case a previous run left them changed)
sysctl -w net.core.rmem_max=4194304 net.core.rmem_default=212992 >/dev/null

echo "== copy working tree (includes gitignored bpf generated files) ==" | tee -a "$OUT"
rm -rf "$WS"
mkdir -p "$WS"
cp -r "$SRC/dae" "$WS/dae"
git -C "$WS/dae" log --oneline -1 | tee -a "$OUT"

echo "== build ==" | tee -a "$OUT"
cd "$WS/dae"
go build -o ./dae-core . 2>&1 | tail -5 | tee -a "$OUT"
ls -la ./dae-core | tee -a "$OUT"

echo "== run P8, sysctls DEFAULT, code SetReadBuffer(8MiB) ==" | tee -a "$OUT"
pkill -9 -f 'dae-core' 2>/dev/null
pkill -9 iperf3 2>/dev/null
ip netns del daelab 2>/dev/null
ip link del dae-lab 2>/dev/null
mkdir -p /sys/fs/bpf
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
sleep 1
ip netns add daelab
ip link add dae-lab type veth peer name dae-peer
ip link set dae-peer netns daelab
ip addr add 10.99.0.1/24 dev dae-lab
ip netns exec daelab ip addr add 10.99.0.2/24 dev dae-peer
ip link set dae-lab up
ip netns exec daelab ip link set dae-peer up
ip netns exec daelab ip link set lo up
ip netns exec daelab ip route add default via 10.99.0.1
sysctl -w net.ipv4.ip_forward=1 >/dev/null
iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -j MASQUERADE 2>/dev/null
iperf3 -s -B 10.99.0.1 -D
cp /root/daes_bench/dae/test-udp.dae /root/rcvbuf-step2.dae
chmod 600 /root/rcvbuf-step2.dae
nohup ./dae-core run -c /root/rcvbuf-step2.dae --disable-pidfile --disable-sudo > /tmp/rcvbuf-step2-dae.log 2>&1 &
sleep 6
echo "rmem_default=$(sysctl -n net.core.rmem_default) rmem_max=$(sysctl -n net.core.rmem_max)" | tee -a "$OUT"
echo "== ingress listener rcvbuf (ss -m):" | tee -a "$OUT"
ss -m -ulnp 2>/dev/null | grep '12345' | tee -a "$OUT"
ip netns exec daelab iperf3 -u -P 8 -b 10G -l 1200 -c 10.99.0.1 -t 12 2>&1 | grep -E 'receiver|SUM' | tee -a "$OUT"
pkill -9 -f 'dae-core' 2>/dev/null
pkill -9 iperf3 2>/dev/null
ip netns del daelab 2>/dev/null
ip link del dae-lab 2>/dev/null
echo "DONE" | tee -a "$OUT"
