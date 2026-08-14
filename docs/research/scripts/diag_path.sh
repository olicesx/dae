#!/bin/bash
# Comprehensive diagnostic: is traffic actually going through dae?
set +e
DAE=/root/daes_bench/rcvbuf/dae/dae-core
CFG=/root/daes_bench/dae/test-udp.dae

setup() {
  pkill -9 -f dae-core 2>/dev/null
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
}

echo "=== A. iptables state BEFORE dae (mangle) ==="
iptables -t mangle -L -n 2>/dev/null | head -15
echo "=== B. iptables state BEFORE dae (nat) ==="
iptables -t nat -L -n 2>/dev/null | head -8

setup
echo "=== C. start dae ==="
cp "$CFG" /root/diag2.dae
chmod 600 /root/diag2.dae
nohup "$DAE" run -c /root/diag2.dae --disable-pidfile --disable-sudo > /tmp/diag2-dae.log 2>&1 &
sleep 7
echo "=== D. dae listeners (tcp+udp) ==="
ss -ltnp 2>/dev/null | grep 12345
ss -lunp 2>/dev/null | grep 12345
echo "(empty above = no 12345 listeners)"
echo "=== E. iptables AFTER dae (mangle TPROXY) ==="
iptables -t mangle -L -n 2>/dev/null | grep -iE 'tproxy|12345|dae' | head -10
echo "=== F. tc filters on dae-lab ==="
tc filter show dev dae-lab ingress 2>/dev/null | head -10
tc filter show dev dae-lab egress 2>/dev/null | head -6
echo "=== G. bpftool programs ==="
bpftool prog show 2>/dev/null | grep -cE 'tc|tproxy' 
echo "=== H. P8 with dae running ==="
ip netns exec daelab iperf3 -u -P 8 -b 10G -l 1200 -c 10.99.0.1 -t 10 2>&1 | grep -E '\[SUM\].*(receiver|sender)' 
echo "=== I. kill dae, P8 again (NAT-only control) ==="
pkill -9 -f dae-core
sleep 2
ip netns exec daelab iperf3 -u -P 8 -b 10G -l 1200 -c 10.99.0.1 -t 10 2>&1 | grep -E '\[SUM\].*(receiver|sender)'
echo "=== J. dae log: bind/listen lines ==="
grep -iE 'bind|listen|tproxy|serve' /tmp/diag2-dae.log | head -12
pkill -9 -f dae-core 2>/dev/null
pkill -9 iperf3 2>/dev/null
ip netns del daelab 2>/dev/null
ip link del dae-lab 2>/dev/null
echo DIAG_DONE
