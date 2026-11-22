#!/usr/bin/env bash
set -euo pipefail

# Benchmark runner with CPU profiling for attack-box hot paths
# Usage: ./scripts/run-benchmarks.sh [package]
# Examples:
#   ./scripts/run-benchmarks.sh                    # Run all benchmarks
#   ./scripts/run-benchmarks.sh internal/secret    # Run secret benchmarks only

readonly REPORTS_DIR="reports/perf"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
readonly TIMESTAMP
readonly RUN_DIR="${REPORTS_DIR}/${TIMESTAMP}"
main() {
    local target="${1:-all}"

    mkdir -p "${RUN_DIR}"

    echo "=== Attack Box Performance Benchmarks ==="
    echo "Timestamp: $(date -Iseconds)"
    echo "Go version: $(go version)"
    echo "GOOS/GOARCH: $(go env GOOS)/$(go env GOARCH)"
    echo "Target: ${target}"
    echo

    case "${target}" in
        all)
            run_benchmarks "internal/secret" "secret"
            run_benchmarks "internal/telemetry" "telemetry"
            run_benchmarks "internal/responder" "responder"
            ;;
        internal/secret|secret)
            run_benchmarks "internal/secret" "secret"
            ;;
        internal/telemetry|telemetry)
            run_benchmarks "internal/telemetry" "telemetry"
            ;;
        internal/responder|responder)
            run_benchmarks "internal/responder" "responder"
            ;;
        *)
            echo "Unknown target: ${target}" >&2
            echo "Valid targets: all, internal/secret, internal/telemetry, internal/responder" >&2
            exit 1
            ;;
    esac

    generate_summary

    echo
    echo "=== Results ==="
    echo "Output directory: ${RUN_DIR}"
    echo "Benchmark results: ${RUN_DIR}/*.bench.txt"
    echo "CPU profiles: ${RUN_DIR}/*.cpu.prof"
    echo "Summary: ${RUN_DIR}/summary.txt"
    echo
    echo "To view a CPU profile:"
    echo "  go tool pprof -http=:8080 ${RUN_DIR}/secret.cpu.prof"
}

run_benchmarks() {
    local package="$1"
    local name="$2"

    echo "--- Running ${name} benchmarks ---"

    echo "Running golden tests first..."
    if ! go test -run='^Test' "./${package}" > /dev/null 2>&1; then
        echo "Golden tests failed for ${package}" >&2
        return 1
    fi
    echo "Golden tests passed"
    echo


    local bench_out="${RUN_DIR}/${name}.bench.txt"
    local cpu_prof="${RUN_DIR}/${name}.cpu.prof"
    local mem_prof="${RUN_DIR}/${name}.mem.prof"

    # Run with CPU profiling
    go test -v \
        -bench=. \
        -benchmem \
        -benchtime=1s \
        -count=5 \
        -cpuprofile="${cpu_prof}" \
        -memprofile="${mem_prof}" \
        "./${package}" \
        | tee "${bench_out}"

    echo "Saved: ${bench_out}, ${cpu_prof}, ${mem_prof}"
    echo
}

generate_summary() {
    local summary="${RUN_DIR}/summary.txt"

    {
        echo "=== Attack Box Benchmark Summary ==="
        echo "Timestamp: $(date -Iseconds)"
        echo "Go version: $(go version)"
        echo

        for bench_file in "${RUN_DIR}"/*.bench.txt; do
            if [[ -f "${bench_file}" ]]; then
                local name
                name=$(basename "${bench_file}" .bench.txt)
                echo "--- ${name} ---"
                grep -E '^Benchmark' "${bench_file}" | tail -20 || true
                echo
            fi
        done

        echo "=== Top Functions by CPU Time ==="
        for prof_file in "${RUN_DIR}"/*.cpu.prof; do
            if [[ -f "${prof_file}" ]]; then
                local name
                name=$(basename "${prof_file}" .cpu.prof)
                echo "--- ${name} ---"
                go tool pprof -top -nodecount=10 "${prof_file}" 2>/dev/null || echo "Profile data unavailable"
                echo
            fi
        done
    } > "${summary}"

    echo "Generated summary: ${summary}"
}

main "$@"
