#!/usr/bin/env bash
#
# Run a bounded real-BPF startup/reload/recovery smoke test for dae.
#
# The script intentionally uses an empty configuration by default. It verifies
# datapath lifecycle and stale-state recovery, not proxy, DNS, or application
# traffic.

set -euo pipefail

binary=./dae
source_config=install/empty.dae
rounds=3
shutdown_timeout_seconds=${DAE_SMOKE_SHUTDOWN_TIMEOUT_SECONDS:-15}

if [ "$#" -ge 1 ]; then
	binary=$1
fi
if [ "$#" -ge 2 ]; then
	source_config=$2
fi
if [ "$#" -ge 3 ]; then
	rounds=$3
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "this smoke test requires root" >&2
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
if [ ! -x "$binary" ]; then
	echo "dae binary is not executable: $binary" >&2
	exit 1
fi
if [ ! -f "$source_config" ]; then
	echo "config file does not exist: $source_config" >&2
	exit 1
fi
for command_name in ip mountpoint stat tc; do
	if ! command -v "$command_name" >/dev/null 2>&1; then
		echo "required command is missing: $command_name" >&2
		exit 1
	fi
done

binary=$(readlink -f "$binary")
source_config=$(readlink -f "$source_config")

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

tmp_dir=$(mktemp -d /tmp/dae-semantic-live-smoke.XXXXXX)
daemon_pid=
mounted_here=0

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
	set +e
	if [ -n "$daemon_pid" ] && kill -0 "$daemon_pid" 2>/dev/null; then
		kill -TERM "$daemon_pid" 2>/dev/null
		if ! wait_for_daemon_exit "$daemon_pid" "$shutdown_timeout_seconds"; then
			kill -KILL "$daemon_pid" 2>/dev/null
			wait_for_daemon_exit "$daemon_pid" 5 || true
		fi
	fi
	ip link del dae0 2>/dev/null
	ip netns del daens 2>/dev/null
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

config_file="$tmp_dir/config.dae"
cp "$source_config" "$config_file"
chmod 600 "$config_file"

start_daemon() {
	local log_file=$1
	"$binary" run -c "$config_file" --disable-sudo --disable-pidfile --disable-timestamp >"$log_file" 2>&1 &
	daemon_pid=$!
}

read_rss_kb() {
	awk '/^VmRSS:/ { print $2; exit }' "/proc/$daemon_pid/status" 2>/dev/null || true
}

observe_rss() {
	local current
	current=$(read_rss_kb)
	if [[ "$current" =~ ^[0-9]+$ ]] && [ "$current" -gt "$max_rss_kb" ]; then
		max_rss_kb=$current
	fi
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

assert_single_internal_filter() {
	local host_count
	local peer_count
	host_count=$(tc filter show dev dae0 ingress | grep -F -c dae_dae0_ingress || true)
	peer_count=$(ip netns exec daens tc filter show dev dae0peer ingress | grep -F -c dae_dae0peer_ingress || true)
	if [ "$host_count" -ne 1 ] || [ "$peer_count" -ne 1 ]; then
		echo "unexpected internal TC filter counts: dae0=$host_count dae0peer=$peer_count" >&2
		cat "$tmp_dir/initial.log" >&2
		return 1
	fi
}

start_daemon "$tmp_dir/initial.log"
wait_for_text "$tmp_dir/initial.log" "Control plane built"
baseline_rss_kb=$(read_rss_kb)
max_rss_kb=$baseline_rss_kb
if ! [[ "$baseline_rss_kb" =~ ^[0-9]+$ ]]; then
	echo "could not read daemon VmRSS" >&2
	exit 1
fi

round=1
while [ "$round" -le "$rounds" ]; do
	kill -USR1 "$daemon_pid"
	wait_for_reload_count "$tmp_dir/initial.log" "$round"
	assert_single_internal_filter
	observe_rss
	round=$((round + 1))
done

if ! stop_daemon "$tmp_dir/initial.log"; then
	exit 1
fi

if [ ! -e /sys/fs/bpf/dae ]; then
	echo "fast-exit did not leave the expected BPF pin root" >&2
	exit 1
fi
# Fast exit closes the dae netns: the dae0/dae0peer (veth or netkit) pair and
# the named daens namespace are removed. Only the BPF pin root is left for the
# next startup to purge, so a subsequent restart must not trip over them.
if ip link show dae0 >/dev/null 2>&1; then
	echo "fast-exit did not tear down the expected dae0 device" >&2
	exit 1
fi
if ip netns list 2>/dev/null | grep -q '^daens'; then
	echo "fast-exit did not tear down the expected daens namespace" >&2
	exit 1
fi

start_daemon "$tmp_dir/recovery.log"
wait_for_text "$tmp_dir/recovery.log" "Control plane built"
observe_rss
if ! grep -Fq "purging stale TC filter" "$tmp_dir/recovery.log"; then
	cat "$tmp_dir/recovery.log" >&2
	echo "recovery startup did not purge stale TC state" >&2
	exit 1
fi

if ! stop_daemon "$tmp_dir/recovery.log"; then
	exit 1
fi

echo "semantic refactor live smoke passed: $rounds reload rounds and stale-state recovery, daemon-rss-baseline=${baseline_rss_kb}KB max=${max_rss_kb}KB"
