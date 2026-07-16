#!/usr/bin/env bash
# Run deterministic real-BPF TCP and UDP throughput tests over a temporary veth.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
binary="$repo_root/dae"
duration=3
udp_bitrate=0
server_ns=dae-semantic-iperf-server
host_link=dsmoke-iperf0
peer_link=dsmoke-ipf-peer
host_ip=198.21.0.1
server_ip=198.21.0.2
tcp_port=19000
udp_port=19001

if [ "$#" -ge 1 ]; then binary=$1; fi
if [ "$#" -ge 2 ]; then duration=$2; fi
if [ "$#" -ge 3 ]; then udp_bitrate=$3; fi
if [ "$(id -u)" -ne 0 ]; then echo "this smoke test requires root" >&2; exit 1; fi
for command_name in iperf3 ip mountpoint python3; do
	if ! command -v "$command_name" >/dev/null 2>&1; then echo "required command is missing: $command_name" >&2; exit 1; fi
done
if [ ! -x "$binary" ]; then echo "dae binary is not executable: $binary" >&2; exit 1; fi
if ! [[ "$duration" =~ ^[1-9][0-9]*$ ]]; then echo "duration must be a positive integer" >&2; exit 1; fi
if ! [[ "$udp_bitrate" =~ ^(0|[0-9]+([KMG](/[0-9]+)?)?)$ ]]; then
	echo "udp bitrate must be 0 or an iperf3 rate such as 100M" >&2
	exit 1
fi

binary=$(readlink -f "$binary")
for resource in "$host_link" dae0; do
	if ip link show "$resource" >/dev/null 2>&1; then echo "$resource already exists; refusing to touch an existing deployment" >&2; exit 1; fi
done
for namespace in "$server_ns" daens; do
	if ip netns list 2>/dev/null | grep -q "^$namespace"; then echo "$namespace already exists; refusing to touch an existing deployment" >&2; exit 1; fi
done
if [ -e /sys/fs/bpf/dae ]; then echo "/sys/fs/bpf/dae already exists; refusing to touch an existing deployment" >&2; exit 1; fi

tmp_dir=$(mktemp -d /tmp/dae-semantic-live-iperf.XXXXXX)
daemon_pid=
client_pid=
server_pid=
mounted_here=0
cleanup_done=0

cleanup() {
	if [ "$cleanup_done" -eq 1 ]; then return; fi
	cleanup_done=1
	set +e
	if [ -n "$client_pid" ] && kill -0 "$client_pid" 2>/dev/null; then kill -TERM "$client_pid" 2>/dev/null; wait "$client_pid" 2>/dev/null; fi
	if [ -n "$daemon_pid" ] && kill -0 "$daemon_pid" 2>/dev/null; then
		kill -TERM "$daemon_pid" 2>/dev/null
		sleep 2
		kill -KILL "$daemon_pid" 2>/dev/null
		wait "$daemon_pid" 2>/dev/null
	fi
	if [ -n "$server_pid" ] && kill -0 "$server_pid" 2>/dev/null; then kill -TERM "$server_pid" 2>/dev/null; wait "$server_pid" 2>/dev/null; fi
	ip link del dae0 2>/dev/null
	ip netns del daens 2>/dev/null
	ip link del "$host_link" 2>/dev/null
	ip netns del "$server_ns" 2>/dev/null
	rm -rf /sys/fs/bpf/dae
	if [ "$mounted_here" -eq 1 ]; then umount /sys/fs/bpf 2>/dev/null; fi
	rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

if ! mountpoint -q /sys/fs/bpf; then mount -t bpf bpf /sys/fs/bpf; mounted_here=1; fi
if [ "$(stat -fc '%T' /sys/fs/bpf)" != "bpf_fs" ]; then echo "/sys/fs/bpf is not a bpffs mount" >&2; exit 1; fi

ip netns add "$server_ns"
ip link add "$host_link" type veth peer name "$peer_link"
ip link set "$peer_link" netns "$server_ns"
ip addr add "$host_ip/24" dev "$host_link"
ip link set "$host_link" up
ip netns exec "$server_ns" ip link set lo up
ip netns exec "$server_ns" ip addr add "$server_ip/24" dev "$peer_link"
ip netns exec "$server_ns" ip link set "$peer_link" up

config_file="$tmp_dir/config.dae"
cat >"$config_file" <<EOF
global {
    wan_interface: $host_link
    disable_waiting_network: true
}

routing {
    fallback: direct
}
EOF
chmod 600 "$config_file"

"$binary" run -c "$config_file" --disable-sudo --disable-pidfile --disable-timestamp >"$tmp_dir/daemon.log" 2>&1 &
daemon_pid=$!
wait_log() {
	local text=$1
	for attempt in {1..45}; do
		if grep -Fq "$text" "$tmp_dir/daemon.log"; then return 0; fi
		if ! kill -0 "$daemon_pid" 2>/dev/null; then cat "$tmp_dir/daemon.log" >&2; return 1; fi
		sleep 1
	done
	cat "$tmp_dir/daemon.log" >&2
	return 1
}
wait_reload() {
	local expected=$1
	for attempt in {1..45}; do
		if [ "$(grep -F -c '[Reload] Finished' "$tmp_dir/daemon.log" || true)" -ge "$expected" ]; then return 0; fi
		if ! kill -0 "$daemon_pid" 2>/dev/null; then cat "$tmp_dir/daemon.log" >&2; return 1; fi
		sleep 1
	done
	cat "$tmp_dir/daemon.log" >&2
	return 1
}
wait_log "Control plane built"
baseline_fd_count=$(find "/proc/$daemon_pid/fd" -mindepth 1 -maxdepth 1 -type l | wc -l)
max_fd_count=$baseline_fd_count

run_iperf() {
	local name=$1
	local port=$2
	local protocol=$3
	local expected_reload=$4
	local client_args=(iperf3 -c "$server_ip" -p "$port" -t "$duration" -J)
	if [ "$protocol" = "udp" ]; then client_args+=( -u -b "$udp_bitrate" ); fi
	ip netns exec "$server_ns" iperf3 -s -1 -p "$port" >"$tmp_dir/$name-server.log" 2>&1 &
	server_pid=$!
	sleep 0.3
	"${client_args[@]}" >"$tmp_dir/$name.json" 2>"$tmp_dir/$name-client.log" &
	client_pid=$!
	sleep 0.5
	kill -USR2 "$daemon_pid"
	wait_reload "$expected_reload"
	current_fd_count=$(find "/proc/$daemon_pid/fd" -mindepth 1 -maxdepth 1 -type l | wc -l)
	if [ "$current_fd_count" -gt "$max_fd_count" ]; then max_fd_count=$current_fd_count; fi
	if [ "$current_fd_count" -gt $((baseline_fd_count + 8)) ]; then echo "daemon fd count grew after $name reload" >&2; exit 1; fi
	if ! wait "$client_pid"; then cat "$tmp_dir/$name-client.log" >&2; exit 1; fi
	client_pid=
	wait "$server_pid" 2>/dev/null || true
	server_pid=
	python3 - "$tmp_dir/$name.json" "$name" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    report = json.load(stream)
end = report["end"]
summary = end.get("sum_received") or end.get("sum")
sent = end.get("sum_sent") or {}
if not summary or summary.get("bits_per_second", 0) <= 0:
    raise SystemExit("iperf3 did not report positive throughput")
loss = summary.get("lost_percent")
jitter = summary.get("jitter_ms")
loss_text = "n/a" if loss is None else f"{loss:.3f}%"
jitter_text = "n/a" if jitter is None else f"{jitter:.3f}ms"
print(
    f"{sys.argv[2]}-rx-bps={summary['bits_per_second']:.0f}"
    f" tx-bps={sent.get('bits_per_second', 0):.0f}"
    f" loss={loss_text} jitter={jitter_text}"
)
PY
}

run_iperf tcp "$tcp_port" tcp 1 >"$tmp_dir/tcp-result"
run_iperf udp "$udp_port" udp 2 >"$tmp_dir/udp-result"

kill -TERM "$daemon_pid"
wait "$daemon_pid" 2>/dev/null || true
daemon_pid=
tcp_result=$(cat "$tmp_dir/tcp-result")
udp_result=$(cat "$tmp_dir/udp-result")
cleanup
trap - EXIT INT TERM
if ip link show "$host_link" >/dev/null 2>&1 || ip netns list 2>/dev/null | grep -q "^$server_ns" || ip link show dae0 >/dev/null 2>&1 || ip netns list 2>/dev/null | grep -q '^daens' || [ -e /sys/fs/bpf/dae ]; then echo "iperf smoke cleanup left resources behind" >&2; exit 1; fi
echo "semantic refactor local iperf smoke passed: $tcp_result $udp_result, udp-target=$udp_bitrate, daemon-fd-baseline=$baseline_fd_count max=$max_fd_count"
