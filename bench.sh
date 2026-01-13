#!/bin/bash
# Run benchmarks with aligned column output
# Usage: ./bench.sh [pattern] [benchtime] [extra-flags]
# Example: ./bench.sh 'Round' 200ms -benchmem

pattern="${1:-.}"
benchtime="${2:-100ms}"
shift 2 2>/dev/null

go test -bench="$pattern" -benchtime="$benchtime" -run=^$ "$@" 2>&1 | \
    awk '
    /^Benchmark/ {
        name = $1
        iters = $2
        nsop = $3 " " $4
        rest = ""

        for (i = 5; i <= NF; i++) {
            if ($i ~ /^[0-9]/ && $(i+1) == "MB/s") {
                rest = rest sprintf("  %10s MB/s", $i)
                i++
            } else if ($i ~ /^[0-9]/ && $(i+1) == "B/op") {
                rest = rest sprintf("  %8s B/op", $i)
                i++
            } else if ($i ~ /^[0-9]/ && $(i+1) == "allocs/op") {
                rest = rest sprintf("  %6s allocs/op", $i)
                i++
            }
        }

        printf "%-40s  %12s  %14s%s\n", name, iters, nsop, rest
        next
    }
    { print }
    '
