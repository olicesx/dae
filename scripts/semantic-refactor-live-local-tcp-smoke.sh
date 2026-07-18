#!/usr/bin/env bash
#
# Run a deterministic real-BPF WAN-hook TCP flow against a temporary veth peer.
#
# The server is isolated in its own network namespace. The test therefore
# exercises the kernel WAN path without depending on a public endpoint.

set -euo pipefail

binary=./dae
rounds=16
server_ns=dae-semantic-tcp-server
host_link=dsmoke0
peer_link=dsmoke-peer
host_ip=198.18.0.1
server_ip=198.18.0.2
server_port=18080

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
for command_name in curl dd ip mountpoint python3 ss; do
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

tmp_dir=$(mktemp -d /tmp/dae-semantic-live-local-tcp.XXXXXX)
daemon_pid=
request_pid=
server_pid=
mounted_here=0
cleanup_done=0

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
		sleep 2
		kill -KILL "$daemon_pid" 2>/dev/null
		wait "$daemon_pid" 2>/dev/null
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

dd if=/dev/zero of="$tmp_dir/payload" bs=1M count=1 status=none
ip netns exec "$server_ns" python3 -m http.server "$server_port" --bind "$server_ip" --directory "$tmp_dir" >"$tmp_dir/server.log" 2>&1 &
server_pid=$!

server_ready=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
	if curl --noproxy '*' --silent --show-error --fail --head \
		--connect-timeout 1 --max-time 2 "http://$server_ip:$server_port/payload" >/dev/null 2>&1; then
		server_ready=1
		break
	fi
	sleep 1
done
if [ "$server_ready" -ne 1 ]; then
	cat "$tmp_dir/server.log" >&2
	echo "temporary TCP server did not become ready" >&2
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
	(
		curl --noproxy '*' --silent --show-error --fail \
			--connect-timeout 5 --max-time 30 --limit-rate 128k \
			-o /dev/null -w '%{http_code} %{time_connect} %{time_total}\n' \
			"http://$server_ip:$server_port/payload" >"$status_file"
	) &
	request_pid=$!
	sleep 0.2
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
		echo "local TCP request failed during reload round $round" >&2
		exit 1
	fi
	request_pid=
	if ! read -r http_code connect_seconds total_seconds <"$status_file"; then
		echo "missing curl timing result in reload round $round" >&2
		exit 1
	fi
	if [ "$http_code" != "200" ]; then
		echo "unexpected local HTTP status in reload round $round: $http_code" >&2
		exit 1
	fi
	printf '%s\t%s\t%s\n' "$round" "$connect_seconds" "$total_seconds" >>"$timing_file"
	round=$((round + 1))
done

kill -TERM "$daemon_pid"
wait "$daemon_pid" 2>/dev/null || true
daemon_pid=

latency_summary=$(awk -F '\t' '
{
	connect += $2 * 1000
	total += $3 * 1000
	if (count == 0 || $2 * 1000 < connect_min) connect_min = $2 * 1000
	if (count == 0 || $2 * 1000 > connect_max) connect_max = $2 * 1000
	if (count == 0 || $3 * 1000 < total_min) total_min = $3 * 1000
	if (count == 0 || $3 * 1000 > total_max) total_max = $3 * 1000
	count++
}
END {
	if (count == 0) exit 1
	printf "connect-ms[min=%.1f max=%.1f avg=%.1f] total-ms[min=%.1f max=%.1f avg=%.1f]", connect_min, connect_max, connect / count, total_min, total_max, total / count
}' "$timing_file")

cleanup
trap - EXIT INT TERM
if ip link show "$host_link" >/dev/null 2>&1 ||
	ip netns list 2>/dev/null | grep -q "^$server_ns" ||
	ip link show dae0 >/dev/null 2>&1 ||
	ip netns list 2>/dev/null | grep -q '^daens' ||
	[ -e /sys/fs/bpf/dae ]; then
	echo "local TCP smoke cleanup left resources behind" >&2
	exit 1
fi

echo "semantic refactor local TCP smoke passed: $rounds veth WAN-hook HTTP requests during reload, daemon-fd-baseline=$baseline_fd_count max=$max_fd_count, $latency_summary"
