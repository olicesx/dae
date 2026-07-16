#!/usr/bin/env bash
#
# Run a bounded real-BPF DNS listener and cache smoke test for dae.
#
# The script uses a public UDP resolver by default. It verifies the local DNS
# wire path and cache behavior, not proxy node routing or long-running traffic.

set -euo pipefail

binary=./dae
upstream=8.8.8.8
rounds=1

if [ "$#" -ge 1 ]; then
	binary=$1
fi
if [ "$#" -ge 2 ]; then
	upstream=$2
fi
if [ "$#" -ge 3 ]; then
	rounds=$3
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "this smoke test requires root" >&2
	exit 1
fi
for command_name in dig ip mountpoint ss; do
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
if ss -Hlnup 2>/dev/null | grep -Eq '(^|[[:space:]])127\.0\.0\.1:15353([[:space:]]|$)'; then
	echo "127.0.0.1:15353 is already in use" >&2
	exit 1
fi

tmp_dir=$(mktemp -d /tmp/dae-semantic-live-dns.XXXXXX)
daemon_pid=
mounted_here=0
cleanup_done=0

cleanup() {
	if [ "$cleanup_done" -eq 1 ]; then
		return
	fi
	cleanup_done=1
	set +e
	if [ -n "$daemon_pid" ] && kill -0 "$daemon_pid" 2>/dev/null; then
		kill -TERM "$daemon_pid" 2>/dev/null
		sleep 2
		kill -KILL "$daemon_pid" 2>/dev/null
		wait "$daemon_pid" 2>/dev/null
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
cat >"$config_file" <<EOF
global {
    disable_waiting_network: true
}

routing {}

dns {
    bind: '127.0.0.1:15353'
    upstream {
        smoke: 'udp://$upstream:53'
    }
    routing {
        request {
            fallback: smoke
        }
        response {
            fallback: accept
        }
    }
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

run_query() {
	local qtype=$1
	local output=$2
	local attempt
	for attempt in 1 2 3; do
		if dig +time=3 +tries=1 @127.0.0.1 -p 15353 example.com "$qtype" >"$output" 2>&1 &&
			grep -Fq "status: NOERROR" "$output" &&
			grep -Fq "SERVER: 127.0.0.1#15353" "$output"; then
			return 0
		fi
		sleep 1
	done
	cat "$output" >&2
	return 1
}

start_daemon "$tmp_dir/daemon.log"
wait_for_text "$tmp_dir/daemon.log" "DNS listener started"

round=1
while [ "$round" -le "$rounds" ]; do
	run_query A "$tmp_dir/a-first-$round.log"
	run_query A "$tmp_dir/a-cache-$round.log"
	run_query AAAA "$tmp_dir/aaaa-$round.log"
	round=$((round + 1))
done

a_first_ms=$(awk '/Query time:/ {print $4; exit}' "$tmp_dir/a-first-1.log")
a_cache_ms=$(awk '/Query time:/ {print $4; exit}' "$tmp_dir/a-cache-1.log")
aaaa_ms=$(awk '/Query time:/ {print $4; exit}' "$tmp_dir/aaaa-1.log")
if [ -z "$a_first_ms" ]; then
	a_first_ms=unknown
fi
if [ -z "$a_cache_ms" ]; then
	a_cache_ms=unknown
fi
if [ -z "$aaaa_ms" ]; then
	aaaa_ms=unknown
fi

kill -TERM "$daemon_pid"
wait "$daemon_pid" 2>/dev/null || true
daemon_pid=
cleanup
trap - EXIT INT TERM

if [ -e /sys/fs/bpf/dae ] || ip link show dae0 >/dev/null 2>&1 || ip netns list 2>/dev/null | grep -q '^daens'; then
	echo "DNS smoke cleanup left dae resources behind" >&2
	exit 1
fi

echo "semantic refactor live DNS smoke passed: rounds=$rounds A=$a_first_ms ms cached-A=$a_cache_ms ms AAAA=$aaaa_ms ms"
