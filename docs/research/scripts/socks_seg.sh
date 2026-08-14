#!/bin/bash
# Segment decomposition: dae->proxy only (count-only), with pprof of dae.
set +e
WS=/root/daes_bench/rcvbuf
OUT=/tmp/socks_seg.log
: > "$OUT"

pkill -9 -f 'dae-core' 2>/dev/null
pkill -9 -x socks_proxy 2>/dev/null
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
sysctl -w net.core.rmem_max=4194304 net.core.rmem_default=212992 >/dev/null

echo "== start proxy (count-only) ==" | tee -a "$OUT"
nohup /root/udp_probe/socks_proxy -listen :1080 -relay-target 127.0.0.1:5201 -count-only > /tmp/seg-proxy.log 2>&1 &
sleep 1
cp /root/daes_bench/dae/test-socks-hp.dae /root/seg.dae
chmod 600 /root/seg.dae
echo "== start dae (batch-write build) ==" | tee -a "$OUT"
nohup "$WS/dae/dae-core" run -c /root/seg.dae --disable-pidfile --disable-sudo > /tmp/seg-dae.log 2>&1 &
DAEPID=$!
sleep 7
if ! kill -0 "$DAEPID" 2>/dev/null; then echo "dae DIED"; tail -5 /tmp/seg-dae.log; exit 1; fi

WAN_IP=$(ip addr show eth1 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
[ -z "$WAN_IP" ] && WAN_IP=$(ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1)
echo "WAN_IP=$WAN_IP" | tee -a "$OUT"

echo "== sender 8 flows 12s (dae->proxy segment) ==" | tee -a "$OUT"
ip netns exec daelab /root/hp/sender -target ${WAN_IP}:5201 -flows 8 -duration 12s > /tmp/seg-snd.log 2>&1 &
SENDPID=$!
sleep 4
curl -s -m 10 "http://127.0.0.1:6060/debug/pprof/profile?seconds=6" -o /tmp/seg-dae-cpu.prof 2>/dev/null
echo "pprof: $(stat -c%s /tmp/seg-dae-cpu.prof 2>/dev/null) bytes" | tee -a "$OUT"
wait $SENDPID
sleep 2
echo "--- sender report ---" | tee -a "$OUT"
tail -3 /tmp/seg-snd.log | tee -a "$OUT"
echo "--- proxy counted (dae->proxy throughput) ---" | tee -a "$OUT"
tail -3 /tmp/seg-proxy.log | tee -a "$OUT"
echo "--- dae errors ---" | tee -a "$OUT"
grep -cE 'level=error' /tmp/seg-dae.log | tee -a "$OUT"

echo "== pprof top (if profile non-empty) ==" | tee -a "$OUT"
if [ -s /tmp/seg-dae-cpu.prof ]; then
  cd /root/daes_bench/rcvbuf/dae
  go tool pprof -top -nodecount=20 /tmp/seg-dae-cpu.prof 2>/dev/null | head -30 | tee -a "$OUT"
fi

pkill -9 -f 'dae-core' 2>/dev/null
pkill -9 -x socks_proxy 2>/dev/null
pkill -9 -x sender 2>/dev/null
ip netns del daelab 2>/dev/null
ip link del dae-lab 2>/dev/null
echo DONE | tee -a "$OUT"
