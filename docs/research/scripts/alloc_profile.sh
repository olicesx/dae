#!/bin/bash
# Allocation profile of the full socks-path (ingress -> dispatch -> endpoint ->
# aggregator -> socks5 encapsulation) under saturated 8-flow UDP load.
set +e
WS=/root/daes_bench/rcvbuf
OUT=/tmp/alloc_profile.log
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
nohup /root/udp_probe/socks_proxy -listen :1080 -relay-target 127.0.0.1:5201 -count-only > /tmp/alloc-proxy.log 2>&1 &
sleep 1
cp /root/daes_bench/dae/test-socks-hp.dae /root/alloc.dae
chmod 600 /root/alloc.dae
nohup "$WS/dae/dae-core" run -c /root/alloc.dae --disable-pidfile --disable-sudo > /tmp/alloc-dae.log 2>&1 &
sleep 7
WAN_IP=$(ip addr show eth1 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
[ -z "$WAN_IP" ] && WAN_IP=$(ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1)
ip netns exec daelab /root/hp/sender -target ${WAN_IP}:5201 -flows 8 -duration 6s > /tmp/alloc-snd.log 2>&1 &
SENDPID=$!
sleep 3
curl -s -m 8 "http://127.0.0.1:6060/debug/pprof/heap" -o /tmp/alloc-heap.prof 2>/dev/null
wait $SENDPID
sleep 1
echo "== alloc_space top ==" | tee -a "$OUT"
cd "$WS/dae"
go tool pprof -alloc_space -top -nodecount=18 /tmp/alloc-heap.prof 2>/dev/null | head -28 | tee -a "$OUT"
echo "== alloc_objects top ==" | tee -a "$OUT"
go tool pprof -alloc_objects -top -nodecount=15 /tmp/alloc-heap.prof 2>/dev/null | head -25 | tee -a "$OUT"
pkill -9 -f 'dae-core' 2>/dev/null
pkill -9 -x socks_proxy 2>/dev/null
pkill -9 -x sender 2>/dev/null
ip netns del daelab 2>/dev/null
ip link del dae-lab 2>/dev/null
echo DONE | tee -a "$OUT"
