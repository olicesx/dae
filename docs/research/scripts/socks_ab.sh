#!/bin/bash
# socks-path P8 A/B: BASE (e628af76, no SetReadBuffer) vs FIX (070201f7, 8MiB).
# Traffic: netns sender -> dae tproxy (dport 5201 -> socks5-grp) -> socks_proxy
#          -> receiver (loopback :5201). receiver rcvbuf identical in both arms.
set +e
export GOPROXY=https://goproxy.cn,direct
export GOTOOLCHAIN=auto
WS=/root/daes_bench/rcvbuf
OUT=/tmp/socks_ab.log
: > "$OUT"

# ---- build both binaries ----
echo "== build BASE e628af76 ==" | tee -a "$OUT"
cd "$WS/dae"
git checkout -q e628af76 2>&1 | tail -1
go build -o "$WS/dae-core-base" . 2>&1 | tail -3
echo "== build FIX 070201f7 ==" | tee -a "$OUT"
git checkout -q 070201f7 2>&1 | tail -1
go build -o "$WS/dae-core-fix" . 2>&1 | tail -3
ls -la "$WS"/dae-core-base "$WS"/dae-core-fix | tee -a "$OUT"

sysctl -w net.core.rmem_max=4194304 net.core.rmem_default=212992 >/dev/null

run_socks() {
  local label=$1
  local bin=$2
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
  nohup /root/udp_probe/socks_proxy -listen :1080 -relay-target 127.0.0.1:5201 > /tmp/socks-proxy-$label.log 2>&1 &
  sleep 1
  nohup /root/udp_probe/receiver -addr :5201 -duration 15s -flows 8 > /tmp/socks-recv-$label.log 2>&1 &
  sleep 1
  cp /root/daes_bench/dae/test-socks-hp.dae /root/socks-ab.dae
  chmod 600 /root/socks-ab.dae
  nohup "$bin" run -c /root/socks-ab.dae --disable-pidfile --disable-sudo > /tmp/socks-dae-$label.log 2>&1 &
  DAEPID=$!
  sleep 7
  if ! kill -0 "$DAEPID" 2>/dev/null; then
    echo "[$label] dae DIED" | tee -a "$OUT"
    tail -8 /tmp/socks-dae-$label.log | tee -a "$OUT"
    return
  fi
  WAN_IP=$(ip addr show eth1 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
  [ -z "$WAN_IP" ] && WAN_IP=$(ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1)
  echo "== [$label] WAN_IP=$WAN_IP rmem_default=$(sysctl -n net.core.rmem_default)" | tee -a "$OUT"
  # sample dae CPU during the run
  ( for i in $(seq 1 12); do
      awk '{print $14+$15}' /proc/$DAEPID/stat 2>/dev/null
      sleep 1
    done > /tmp/socks-cpu-$label.raw ) &
  CPUPID=$!
  ip netns exec daelab /root/hp/sender -target ${WAN_IP}:5201 -flows 8 -duration 12s > /tmp/socks-sender-$label.log 2>&1
  wait $CPUPID 2>/dev/null
  sleep 2
  echo "--- receiver report [$label] ---" | tee -a "$OUT"
  cat /tmp/socks-recv-$label.log | tee -a "$OUT"
  echo "--- dae CPU ticks (avg user+sys of 12 samples) ---" | tee -a "$OUT"
  awk '{s+=$1; n++} END {printf "avg_ticks/sample=%.1f (2 ticks=1 core-second; 12 cores; 100%% core = ~20000ticks/hz? no: ticks per second per core = HZ)\n", s/n}' /tmp/socks-cpu-$label.raw | tee -a "$OUT"
  pkill -9 -f 'dae-core' 2>/dev/null
  pkill -9 -x sender 2>/dev/null
  sleep 1
}

run_socks BASE "$WS/dae-core-base"
run_socks FIX "$WS/dae-core-fix"

pkill -9 -x receiver 2>/dev/null
pkill -9 -x socks_proxy 2>/dev/null
ip netns del daelab 2>/dev/null
ip link del dae-lab 2>/dev/null
echo DONE | tee -a "$OUT"
