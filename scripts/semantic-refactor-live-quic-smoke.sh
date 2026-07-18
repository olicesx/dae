#!/usr/bin/env bash
# Run a real-BPF WAN-hook public HTTP/3 request while reloading dae.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
binary="$repo_root/dae"
target=https://cloudflare-quic.com/
rounds=8

if [ "$#" -ge 1 ]; then binary=$1; fi
if [ "$#" -ge 2 ]; then target=$2; fi
if [ "$#" -ge 3 ]; then rounds=$3; fi
if [ "$(id -u)" -ne 0 ]; then echo "this smoke test requires root" >&2; exit 1; fi
for command_name in go ip mountpoint ss; do
	if ! command -v "$command_name" >/dev/null 2>&1; then echo "required command is missing: $command_name" >&2; exit 1; fi
done
if [ ! -x "$binary" ]; then echo "dae binary is not executable: $binary" >&2; exit 1; fi
if ! [[ "$rounds" =~ ^[1-9][0-9]*$ ]]; then echo "rounds must be a positive integer" >&2; exit 1; fi
if [[ "$target" != https://* ]]; then echo "target must use https://" >&2; exit 1; fi

binary=$(readlink -f "$binary")
if ip link show dae0 >/dev/null 2>&1; then echo "dae0 already exists; refusing to touch an existing deployment" >&2; exit 1; fi
if ip netns list 2>/dev/null | grep -q '^daens'; then echo "daens already exists; refusing to touch an existing deployment" >&2; exit 1; fi
if [ -e /sys/fs/bpf/dae ]; then echo "/sys/fs/bpf/dae already exists; refusing to touch an existing deployment" >&2; exit 1; fi

tmp_dir=$(mktemp -d /tmp/dae-semantic-live-quic.XXXXXX)
daemon_pid=
request_pid=
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
	rm -rf /sys/fs/bpf/dae
	if [ "$mounted_here" -eq 1 ]; then umount /sys/fs/bpf 2>/dev/null; fi
	rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

if ! mountpoint -q /sys/fs/bpf; then mount -t bpf bpf /sys/fs/bpf; mounted_here=1; fi
if [ "$(stat -fc '%T' /sys/fs/bpf)" != "bpf_fs" ]; then echo "/sys/fs/bpf is not a bpffs mount" >&2; exit 1; fi

cd "$repo_root"
go build -o "$tmp_dir/dae-quic-helper" ./scripts/semantic-refactor-quic-helper
config_file="$tmp_dir/config.dae"
cat >"$config_file" <<EOF
global {
    wan_interface: auto
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
		if [ "$(grep -F -c '[Reload] Finished' "$tmp_dir/daemon.log" || true)" -ge "$expected" ] &&
			[ "$(grep -F -c '[Reload] Retired old control plane' "$tmp_dir/daemon.log" || true)" -ge "$expected" ]; then return 0; fi
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
	request_pid=
	"$tmp_dir/dae-quic-helper" http3-client "$target" >"$status_file" 2>"$tmp_dir/request-$round.log" &
	request_pid=$!
	sleep 0.1
	kill -USR1 "$daemon_pid"
	wait_reload "$round"
	current_fd_count=$(find "/proc/$daemon_pid/fd" -mindepth 1 -maxdepth 1 -type l | wc -l)
	if [ "$current_fd_count" -gt "$max_fd_count" ]; then max_fd_count=$current_fd_count; fi
	if [ "$current_fd_count" -gt $((baseline_fd_count + 8)) ]; then echo "daemon fd count grew after reload round $round" >&2; exit 1; fi
	if ! wait "$request_pid"; then cat "$tmp_dir/request-$round.log" >&2; cat "$tmp_dir/daemon.log" >&2; exit 1; fi
	request_pid=
	read -r protocol_status status_field bytes_field elapsed_field <"$status_file"
	if [ "$protocol_status" != "http3" ] || [ "$status_field" != "status=200" ]; then
		cat "$status_file" >&2
		exit 1
	fi
	elapsed_value=${elapsed_field#elapsed-ms=}
	printf '%s\t%s\n' "$round" "$elapsed_value" >>"$timing_file"
	round=$((round + 1))
done

kill -TERM "$daemon_pid"
wait "$daemon_pid" 2>/dev/null || true
daemon_pid=

latency_summary=$(awk -F '\t' '
{
    total += $2
    if (count == 0 || $2 < minimum) minimum = $2
    if (count == 0 || $2 > maximum) maximum = $2
    count++
}
END {
    if (count == 0) exit 1
    printf "http3-ms[min=%.1f max=%.1f avg=%.1f]", minimum, maximum, total / count
}' "$timing_file")
cleanup
trap - EXIT INT TERM
if ip link show dae0 >/dev/null 2>&1 || ip netns list 2>/dev/null | grep -q '^daens' || [ -e /sys/fs/bpf/dae ]; then echo "public QUIC smoke cleanup left resources behind" >&2; exit 1; fi
echo "semantic refactor public QUIC smoke passed: $rounds HTTP/3 requests during reload to $target, daemon-fd-baseline=$baseline_fd_count max=$max_fd_count, $latency_summary"
