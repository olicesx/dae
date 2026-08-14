#!/bin/bash
# rcvbuf hypothesis, step 1 (hypothesis screen, zero code change):
# UDP P8 via dae HEAD binary, baseline (rmem_default=212992) vs rmem=8MiB.
# If loss drops sharply -> rcvbuf is on the loss path -> step 2 (code, dae-only).
set +e
DAE=/root/daes_bench/ab/head/dae/dae
CFG=/root/daes_bench/dae/test-udp.dae
OUT=/tmp/rcvbuf_step1.log
: > "$OUT"

run_p8() {
  local label=$1
  pkill -9 -f 'dae-core' 2>/dev/null
  pkill -9 -f '/ab/head/dae/dae' 2>/dev/null
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
  cp "$CFG" /root/rcvbuf-test.dae
  chmod 600 /root/rcvbuf-test.dae
  nohup "$DAE" run -c /root/rcvbuf-test.dae --disable-pidfile --disable-sudo > /tmp/rcvbuf-dae-$label.log 2>&1 &
  sleep 6
  echo "### $label | rmem_default=$(sysctl -n net.core.rmem_default) rmem_max=$(sysctl -n net.core.rmem_max)" | tee -a "$OUT"
  if grep -qE 'fatal|FATA' /tmp/rcvbuf-dae-$label.log; then
    echo "dae FAILED to start:" | tee -a "$OUT"
    tail -5 /tmp/rcvbuf-dae-$label.log | tee -a "$OUT"
    return
  fi
  ip netns exec daelab iperf3 -u -P 8 -b 10G -l 1200 -c 10.99.0.1 -t 12 2>&1 \
    | grep -E '\[ *[0-9]+\].*receiver|SUM|sender|out.of.order|Datagrams' | tee -a "$OUT"
  pkill -9 -f '/ab/head/dae/dae' 2>/dev/null
  pkill -9 iperf3 2>/dev/null
  sleep 1
}

echo "== step1: baseline =="
run_p8 baseline
echo "== step1: rmem 8MiB =="
sysctl -w net.core.rmem_max=8388608 net.core.rmem_default=8388608 >/dev/null
run_p8 rmem8m
echo "== restore sysctls =="
sysctl -w net.core.rmem_max=4194304 net.core.rmem_default=212992 >/dev/null
pkill -9 -f '/ab/head/dae/dae' 2>/dev/null
pkill -9 iperf3 2>/dev/null
ip netns del daelab 2>/dev/null
ip link del dae-lab 2>/dev/null
echo "DONE" | tee -a "$OUT"
