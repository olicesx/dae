#!/usr/bin/env bash
#
# Run a deterministic real-BPF WAN-hook UDP flow against a temporary veth peer.
#
# The server is isolated in its own network namespace and delays each echo so
# every request overlaps the reload that follows its send.

set -euo pipefail

binary=./dae
rounds=16
server_ns=dae-semantic-udp-server
host_link=dsmoke-udp0
peer_link=dsmoke-udp-peer
host_ip=198.19.0.1
server_ip=198.19.0.2
server_port=18081
shutdown_timeout_seconds=${DAE_SMOKE_SHUTDOWN_TIMEOUT_SECONDS:-15}

if [ "$#" -ge 1 ]; then
	binary=$1
fi
if [ "$#" -ge 2 ]; then
	rounds=$2
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "this smoke test requires root" >&2
	exit 1
fi
for command_name in ip mountpoint python3; do
	if ! command -v "$command_name" >/dev/null 2>&1; then
		echo "required command is missing: $command_name" >&2
		exit 1
	fi
done
if [ ! -x "$binary" ]; then
	echo "dae binary is not executable: $binary" >&2
	exit 1
fi
if ! [[ "$rounds" =~ ^[1-9][0-9]*$ ]]; then
	echo "rounds must be a positive integer" >&2
	exit 1
fi
if ! [[ "$shutdown_timeout_seconds" =~ ^[1-9][0-9]*$ ]]; then
	echo "DAE_SMOKE_SHUTDOWN_TIMEOUT_SECONDS must be a positive integer" >&2
	exit 1
fi

binary=$(readlink -f "$binary")
if ip link show "$host_link" >/dev/null 2>&1; then
	echo "$host_link already exists; refusing to touch an existing deployment" >&2
	exit 1
fi
if ip netns list 2>/dev/null | grep -q "^$server_ns"; then
	echo "$server_ns already exists; refusing to touch an existing deployment" >&2
	exit 1
fi
if ip link show dae0 >/dev/null 2>&1; then
	echo "dae0 already exists; refusing to touch an existing deployment" >&2
	exit 1
fi
if ip netns list 2>/dev/null | grep -q '^daens'; then
	echo "daens already exists; refusing to touch an existing deployment" >&2
	exit 1
fi
if [ -e /sys/fs/bpf/dae ]; then
	echo "/sys/fs/bpf/dae already exists; refusing to touch an existing deployment" >&2
	exit 1
fi

tmp_dir=$(mktemp -d /tmp/dae-semantic-live-local-udp.XXXXXX)
daemon_pid=
request_pid=
server_pid=
mounted_here=0
cleanup_done=0

daemon_has_exited() {
	local pid=$1
	local state
	if ! kill -0 "$pid" 2>/dev/null; then
		return 0
	fi
	state=$(awk '{ print $3 }' "/proc/$pid/stat" 2>/dev/null || true)
	[ "$state" = "Z" ]
}

wait_for_daemon_exit() {
	local pid=$1
	local timeout_seconds=$2
	local deadline=$((SECONDS + timeout_seconds))
	while ! daemon_has_exited "$pid"; do
		if [ "$SECONDS" -ge "$deadline" ]; then
			return 1
		fi
		sleep 1
	done
	wait "$pid" 2>/dev/null || true
}

stop_daemon() {
	local log_file=$1
	local pid=$daemon_pid
	if [ -z "$pid" ]; then
		return 0
	fi
	kill -TERM "$pid" 2>/dev/null || true
	if ! wait_for_daemon_exit "$pid" "$shutdown_timeout_seconds"; then
		echo "daemon did not exit within ${shutdown_timeout_seconds}s" >&2
		if [ -f "$log_file" ]; then
			cat "$log_file" >&2
		fi
		return 1
	fi
	daemon_pid=
}

cleanup() {
	if [ "$cleanup_done" -eq 1 ]; then
		return
	fi
	cleanup_done=1
	set +e
	if [ -n "$request_pid" ] && kill -0 "$request_pid" 2>/dev/null; then
		kill -TERM "$request_pid" 2>/dev/null
		wait "$request_pid" 2>/dev/null
	fi
	if [ -n "$daemon_pid" ] && kill -0 "$daemon_pid" 2>/dev/null; then
		kill -TERM "$daemon_pid" 2>/dev/null
		if ! wait_for_daemon_exit "$daemon_pid" "$shutdown_timeout_seconds"; then
			kill -KILL "$daemon_pid" 2>/dev/null
			wait_for_daemon_exit "$daemon_pid" 5 || true
		fi
	fi
	ip link del dae0 2>/dev/null
	ip netns del daens 2>/dev/null
	if [ -n "$server_pid" ] && kill -0 "$server_pid" 2>/dev/null; then
		kill -TERM "$server_pid" 2>/dev/null
		wait "$server_pid" 2>/dev/null
	fi
	ip link del "$host_link" 2>/dev/null
	ip netns del "$server_ns" 2>/dev/null
	rm -rf /sys/fs/bpf/dae
	if [ "$mounted_here" -eq 1 ]; then
		umount /sys/fs/bpf 2>/dev/null
	fi
	rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

if ! mountpoint -q /sys/fs/bpf; then
	mount -t bpf bpf /sys/fs/bpf
	mounted_here=1
fi
if [ "$(stat -fc '%T' /sys/fs/bpf)" != "bpf_fs" ]; then
	echo "/sys/fs/bpf is not a bpffs mount" >&2
	exit 1
fi

ip netns add "$server_ns"
ip link add "$host_link" type veth peer name "$peer_link"
ip link set "$peer_link" netns "$server_ns"
ip addr add "$host_ip/24" dev "$host_link"
ip link set "$host_link" up
ip netns exec "$server_ns" ip link set lo up
ip netns exec "$server_ns" ip addr add "$server_ip/24" dev "$peer_link"
ip netns exec "$server_ns" ip link set "$peer_link" up

cat >"$tmp_dir/udp_server.py" <<'PY'
import socket
import sys
import time

address = (sys.argv[1], int(sys.argv[2]))
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(address)
while True:
    data, peer = sock.recvfrom(65535)
    if data == b"__stop__":
        break
    time.sleep(0.25)
    sock.sendto(b"echo:" + data, peer)
PY

cat >"$tmp_dir/udp_client.py" <<'PY'
import socket
import sys
import time

source = sys.argv[1]
target = (sys.argv[2], int(sys.argv[3]))
payload = ("dae-udp-round-" + sys.argv[4]).encode()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((source, 0))
sock.settimeout(5)
started = time.monotonic()
sock.sendto(payload, target)
data, _ = sock.recvfrom(65535)
elapsed = (time.monotonic() - started) * 1000
if data != b"echo:" + payload:
    raise SystemExit("unexpected UDP echo payload")
print("ok %.1f" % elapsed)
PY

ip netns exec "$server_ns" python3 -u "$tmp_dir/udp_server.py" "$server_ip" "$server_port" >"$tmp_dir/server.log" 2>&1 &
server_pid=$!

server_ready=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
	if python3 "$tmp_dir/udp_client.py" "$host_ip" "$server_ip" "$server_port" ready >/dev/null 2>&1; then
		server_ready=1
		break
	fi
	sleep 1
done
if [ "$server_ready" -ne 1 ]; then
	cat "$tmp_dir/server.log" >&2
	echo "temporary UDP server did not become ready" >&2
	exit 1
fi

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

start_daemon() {
	local log_file=$1
	"$binary" run -c "$config_file" --disable-sudo --disable-pidfile --disable-timestamp >"$log_file" 2>&1 &
	daemon_pid=$!
}

wait_for_text() {
	local log_file=$1
	local text=$2
	local attempt
	for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45; do
		if grep -Fq "$text" "$log_file"; then
			return 0
		fi
		if ! kill -0 "$daemon_pid" 2>/dev/null; then
			cat "$log_file" >&2
			return 1
		fi
		sleep 1
	done
	cat "$log_file" >&2
	return 1
}

wait_for_reload_count() {
	local log_file=$1
	local expected=$2
	local attempt
	local finished
	local retired
	for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45; do
		finished=$(grep -F -c "[Reload] Finished" "$log_file" || true)
		retired=$(grep -F -c "[Reload] Retired old control plane" "$log_file" || true)
		if [ "$finished" -ge "$expected" ] && [ "$retired" -ge "$expected" ]; then
			return 0
		fi
		if ! kill -0 "$daemon_pid" 2>/dev/null; then
			cat "$log_file" >&2
			return 1
		fi
		sleep 1
	done
	cat "$log_file" >&2
	return 1
}

start_daemon "$tmp_dir/daemon.log"
wait_for_text "$tmp_dir/daemon.log" "Control plane built"
baseline_fd_count=$(find "/proc/$daemon_pid/fd" -mindepth 1 -maxdepth 1 -type l | wc -l)
max_fd_count=$baseline_fd_count
timing_file="$tmp_dir/timing.tsv"

round=1
while [ "$round" -le "$rounds" ]; do
	status_file="$tmp_dir/status-$round"
	request_pid=
	python3 "$tmp_dir/udp_client.py" "$host_ip" "$server_ip" "$server_port" "$round" >"$status_file" 2>&1 &
	request_pid=$!
	sleep 0.05
	kill -USR1 "$daemon_pid"
	wait_for_reload_count "$tmp_dir/daemon.log" "$round"
	current_fd_count=$(find "/proc/$daemon_pid/fd" -mindepth 1 -maxdepth 1 -type l | wc -l)
	if [ "$current_fd_count" -gt "$max_fd_count" ]; then
		max_fd_count=$current_fd_count
	fi
	if [ "$current_fd_count" -gt $((baseline_fd_count + 8)) ]; then
		echo "daemon fd count grew from $baseline_fd_count to $current_fd_count after reload round $round" >&2
		exit 1
	fi
	if ! wait "$request_pid"; then
		cat "$tmp_dir/daemon.log" >&2
		cat "$status_file" >&2
		echo "local UDP request failed during reload round $round" >&2
		exit 1
	fi
	request_pid=
	if ! read -r status elapsed <"$status_file"; then
		echo "missing UDP timing result in reload round $round" >&2
		exit 1
	fi
	if [ "$status" != "ok" ]; then
		echo "unexpected UDP status in reload round $round: $status" >&2
		exit 1
	fi
	printf '%s\t%s\n' "$round" "$elapsed" >>"$timing_file"
	round=$((round + 1))
done

if ! stop_daemon "$tmp_dir/daemon.log"; then
	exit 1
fi

latency_summary=$(awk -F '\t' '
{
	if (count == 0 || $2 < min) min = $2
	if (count == 0 || $2 > max) max = $2
	total += $2
	count++
}
END {
	if (count == 0) exit 1
	printf "echo-ms[min=%.1f max=%.1f avg=%.1f]", min, max, total / count
}' "$timing_file")

cleanup
trap - EXIT INT TERM
if ip link show "$host_link" >/dev/null 2>&1 ||
	ip netns list 2>/dev/null | grep -q "^$server_ns" ||
	ip link show dae0 >/dev/null 2>&1 ||
	ip netns list 2>/dev/null | grep -q '^daens' ||
	[ -e /sys/fs/bpf/dae ]; then
	echo "local UDP smoke cleanup left resources behind" >&2
	exit 1
fi

echo "semantic refactor local UDP smoke passed: $rounds veth WAN-hook UDP requests during reload, daemon-fd-baseline=$baseline_fd_count max=$max_fd_count, $latency_summary"
