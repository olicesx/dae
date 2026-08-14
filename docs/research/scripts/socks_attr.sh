#!/bin/bash
# Socks-path loss attribution, scenario A (no dae, receiver direct) and
# C (dae FIX + proxy + receiver, sysctl rmem 8MiB global).
set +e
WS=/root/daes_bench/rcvbuf
OUT=/tmp/socks_attr.log
: > "$OUT"

setup_netns() {
  pkill -9 -f 'dae-core' 2>/dev/null
  pkill -9 -x socks_proxy 2>/dev/null
  pkill -9 -x receiver 2>/dev/null
  pkill -9 -x sender 2>/dev/null
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
}

WAN_IP=$(ip addr show eth1 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
[ -z "$WAN_IP" ] && WAN_IP=$(ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1)
echo "WAN_IP=$WAN_IP" | tee -a "$OUT"

# ---------- A: no dae, receiver direct, default rmem ----------
echo "===== A: receiver direct (no dae, rmem default) =====" | tee -a "$OUT"
setup_netns
sysctl -w net.core.rmem_max=4194304 net.core.rmem_default=212992 >/dev/null
nohup /root/udp_probe/receiver -addr :5201 -duration 15s -flows 8 > /tmp/attrA-recv.log 2>&1 &
sleep 1
ip netns exec daelab /root/hp/sender -target ${WAN_IP}:5201 -flows 8 -duration 12s > /tmp/attrA-snd.log 2>&1
sleep 2
grep -E 'TOTAL|flow' /tmp/attrA-recv.log | tee -a "$OUT"
pkill -9 -x receiver 2>/dev/null
pkill -9 -x sender 2>/dev/null
sleep 1

# ---------- C: dae FIX + socks proxy, rmem 8MiB global ----------
echo "===== C: dae FIX + proxy, rmem 8MiB =====" | tee -a "$OUT"
setup_netns
sysctl -w net.core.rmem_max=8388608 net.core.rmem_default=8388608 >/dev/null
nohup /root/udp_probe/socks_proxy -listen :1080 -relay-target 127.0.0.1:5201 > /tmp/attrC-proxy.log 2>&1 &
sleep 1
nohup /root/udp_probe/receiver -addr :5201 -duration 15s -flows 8 > /tmp/attrC-recv.log 2>&1 &
sleep 1
cp /root/daes_bench/dae/test-socks-hp.dae /root/attrC.dae
chmod 600 /root/attrC.dae
nohup "$WS/dae-core-fix" run -c /root/attrC.dae --disable-pidfile --disable-sudo > /tmp/attrC-dae.log 2>&1 &
DAEPID=$!
sleep 7
( for i in $(seq 1 12); do awk '{print $14+$15}' /proc/$DAEPID/stat 2>/dev/null; sleep 1; done > /tmp/attrC-cpu.raw ) &
CPUPID=$!
ip netns exec daelab /root/hp/sender -target ${WAN_IP}:5201 -flows 8 -duration 12s > /tmp/attrC-snd.log 2>&1
wait $CPUPID 2>/dev/null
sleep 2
grep -E 'TOTAL|flow' /tmp/attrC-recv.log | tee -a "$OUT"
echo "dae CPU ticks: $(awk '{s+=$1} END {printf "%.1f/sample", s/NR}' /tmp/attrC-cpu.raw)" | tee -a "$OUT"
pkill -9 -f 'dae-core' 2>/dev/null
pkill -9 -x receiver 2>/dev/null
pkill -9 -x socks_proxy 2>/dev/null
pkill -9 -x sender 2>/dev/null
ip netns del daelab 2>/dev/null
ip link del dae-lab 2>/dev/null
sysctl -w net.core.rmem_max=4194304 net.core.rmem_default=212992 >/dev/null
echo DONE | tee -a "$OUT"
