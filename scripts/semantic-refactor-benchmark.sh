#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

printf 'timestamp: %s\n' "$(date --iso-8601=seconds)"
uname -srmo
if command -v lscpu >/dev/null 2>&1; then
	lscpu | sed -n -e 's/^Model name:[[:space:]]*//p' \
		-e 's/^CPU(s):[[:space:]]*//p' \
		-e 's/^Thread(s) per core:[[:space:]]*//p' \
		-e 's/^Core(s) per socket:[[:space:]]*//p' \
		-e 's/^Socket(s):[[:space:]]*//p'
fi
if [[ -r /proc/meminfo ]]; then
	grep '^MemTotal:' /proc/meminfo
fi
printf 'go version: '
go version
gomaxprocs=${GOMAXPROCS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')}
printf 'GOMAXPROCS: %s\n' "$gomaxprocs"

if (($# == 0)); then
	set -- -count=5
fi
GOMAXPROCS="$gomaxprocs" go test ./control -run=^$ -bench=BenchmarkPhase -benchmem "$@"
