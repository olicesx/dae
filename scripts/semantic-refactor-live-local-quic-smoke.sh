#!/usr/bin/env bash
# Run a deterministic real-BPF WAN-hook QUIC datagram flow over a temporary veth.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
binary="$repo_root/dae"
rounds=8
server_ns=dae-semantic-quic-server
host_link=dsmoke-quic0
peer_link=dsmq-peer
host_ip=198.20.0.1
server_ip=198.20.0.2
server_port=18443

if [ "$#" -ge 1 ]; then binary=$1; fi
if [ "$#" -ge 2 ]; then rounds=$2; fi
if [ "$(id -u)" -ne 0 ]; then echo "this smoke test requires root" >&2; exit 1; fi
for command_name in go ip mountpoint; do
	if ! command -v "$command_name" >/dev/null 2>&1; then
		echo "required command is missing: $command_name" >&2
		exit 1
	fi
done
if [ ! -x "$binary" ]; then echo "dae binary is not executable: $binary" >&2; exit 1; fi
if ! [[ "$rounds" =~ ^[1-9][0-9]*$ ]]; then echo "rounds must be a positive integer" >&2; exit 1; fi

binary=$(readlink -f "$binary")
for resource in "$host_link" dae0; do
	if ip link show "$resource" >/dev/null 2>&1; then
		echo "$resource already exists; refusing to touch an existing deployment" >&2
		exit 1
	fi
done
for namespace in "$server_ns" daens; do
	if ip netns list 2>/dev/null | grep -q "^$namespace"; then
		echo "$namespace already exists; refusing to touch an existing deployment" >&2
		exit 1
	fi
done
if [ -e /sys/fs/bpf/dae ]; then echo "/sys/fs/bpf/dae already exists; refusing to touch an existing deployment" >&2; exit 1; fi

tmp_dir=$(mktemp -d /tmp/dae-semantic-live-local-quic.XXXXXX)
daemon_pid=
request_pid=
server_pid=
mounted_here=0
cleanup_done=0

cleanup() {
	if [ "$cleanup_done" -eq 1 ]; then return; fi
	cleanup_done=1
	set +e
	if [ -n "$request_pid" ] && kill -0 "$request_pid" 2>/dev/null; then kill -TERM "$request_pid" 2>/dev/null; wait "$request_pid" 2>/dev/null; fi
	if [ -n "$daemon_pid" ] && kill -0 "$daemon_pid" 2>/dev/null; then
		kill -TERM "$daemon_pid" 2>/dev/null
		sleep 2
		kill -KILL "$daemon_pid" 2>/dev/null
		wait "$daemon_pid" 2>/dev/null
	fi
	ip link del dae0 2>/dev/null
	ip netns del daens 2>/dev/null
	if [ -n "$server_pid" ] && kill -0 "$server_pid" 2>/dev/null; then kill -TERM "$server_pid" 2>/dev/null; wait "$server_pid" 2>/dev/null; fi
	ip link del "$host_link" 2>/dev/null
	ip netns del "$server_ns" 2>/dev/null
	rm -rf /sys/fs/bpf/dae
	if [ "$mounted_here" -eq 1 ]; then umount /sys/fs/bpf 2>/dev/null; fi
	rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

if ! mountpoint -q /sys/fs/bpf; then mount -t bpf bpf /sys/fs/bpf; mounted_here=1; fi
if [ "$(stat -fc '%T' /sys/fs/bpf)" != "bpf_fs" ]; then echo "/sys/fs/bpf is not a bpffs mount" >&2; exit 1; fi

go build -o "$tmp_dir/quic-helper" ./scripts/semantic-refactor-quic-helper
ip netns add "$server_ns"
ip link add "$host_link" type veth peer name "$peer_link"
ip link set "$peer_link" netns "$server_ns"
ip addr add "$host_ip/24" dev "$host_link"
ip link set "$host_link" up
ip netns exec "$server_ns" ip link set lo up
ip netns exec "$server_ns" ip addr add "$server_ip/24" dev "$peer_link"
ip netns exec "$server_ns" ip link set "$peer_link" up
ip netns exec "$server_ns" "$tmp_dir/quic-helper" server "$server_ip" "$server_port" >"$tmp_dir/server.log" 2>&1 &
server_pid=$!

server_ready=0
for attempt in {1..10}; do
	if "$tmp_dir/quic-helper" client "$server_ip" "$server_port" ready >/dev/null 2>&1; then server_ready=1; break; fi
	sleep 1
done
if [ "$server_ready" -ne 1 ]; then cat "$tmp_dir/server.log" >&2; echo "temporary QUIC server did not become ready" >&2; exit 1; fi

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
timing_file="$tmp_dir/timing.tsv"

round=1
while [ "$round" -le "$rounds" ]; do
	status_file="$tmp_dir/status-$round"
	"$tmp_dir/quic-helper" client "$server_ip" "$server_port" "$round" >"$status_file" 2>&1 &
	request_pid=$!
	sleep 0.1
	kill -USR2 "$daemon_pid"
	wait_reload "$round"
	current_fd_count=$(find "/proc/$daemon_pid/fd" -mindepth 1 -maxdepth 1 -type l | wc -l)
	if [ "$current_fd_count" -gt "$max_fd_count" ]; then max_fd_count=$current_fd_count; fi
	if [ "$current_fd_count" -gt $((baseline_fd_count + 8)) ]; then echo "daemon fd count grew after reload round $round" >&2; exit 1; fi
	if ! wait "$request_pid"; then cat "$tmp_dir/daemon.log" >&2; cat "$status_file" >&2; echo "local QUIC request failed during reload round $round" >&2; exit 1; fi
	request_pid=
	if ! read -r status elapsed <"$status_file" || [ "$status" != "ok" ]; then echo "unexpected QUIC result in reload round $round: $(cat "$status_file")" >&2; exit 1; fi
	printf '%s\t%s\n' "$round" "$elapsed" >>"$timing_file"
	round=$((round + 1))
done

kill -TERM "$daemon_pid"
wait "$daemon_pid" 2>/dev/null || true
daemon_pid=
latency_summary=$(awk -F '\t' '{ if (count == 0 || $2 < min) min=$2; if (count == 0 || $2 > max) max=$2; total+=$2; count++ } END { if (count == 0) exit 1; printf "datagram-ms[min=%.1f max=%.1f avg=%.1f]", min, max, total/count }' "$timing_file")
cleanup
trap - EXIT INT TERM
if ip link show "$host_link" >/dev/null 2>&1 || ip netns list 2>/dev/null | grep -q "^$server_ns" || ip link show dae0 >/dev/null 2>&1 || ip netns list 2>/dev/null | grep -q '^daens' || [ -e /sys/fs/bpf/dae ]; then echo "local QUIC smoke cleanup left resources behind" >&2; exit 1; fi
echo "semantic refactor local QUIC smoke passed: $rounds veth WAN-hook QUIC datagrams during reload, daemon-fd-baseline=$baseline_fd_count max=$max_fd_count, $latency_summary"
