#!/usr/bin/env bash
set -euo pipefail

# Analyze benchmark results and compute opportunity scores
# Usage: ./scripts/analyze-perf.sh <run_dir>

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <run_dir>" >&2
    echo "Example: $0 reports/perf/20241122_153000" >&2
    exit 1
fi

readonly RUN_DIR="$1"

if [[ ! -d "${RUN_DIR}" ]]; then
    echo "Directory not found: ${RUN_DIR}" >&2
    exit 1
fi

main() {
    echo "=== Performance Analysis ==="
    echo "Run directory: ${RUN_DIR}"
    echo
    
    for bench_file in "${RUN_DIR}"/*.bench.txt; do
        if [[ ! -f "${bench_file}" ]]; then
            continue
        fi
        
        local name
        name=$(basename "${bench_file}" .bench.txt)
        # Extract benchmarks with median ns/op (using simple averaging for 5 runs)
        grep '^Benchmark' "${bench_file}" | \
            awk '{name=$1; gsub(/^Benchmark/,"",name); gsub(/-[0-9]+$/,"",name); sum[name]+=$3; count[name]++} 
                 END {for(n in sum) printf "%-40s %10.0f ns/op\n", n, sum[n]/count[n]}' | \
            sort -k2 -n -r | head -15
        
        echo
    done
    
    echo "=== Opportunity Score Calculation ==="
    echo "Score = (ns/op / 1000) * usage_factor"
    echo "where usage_factor is estimated frequency per request"
    echo
    echo "High-impact functions (hotspot score >= 2.0):"
    echo "  - Scrub: ~10,000-100,000 ns/op, called 1-10x per request"
    echo "  - Chunk: ~1,000-10,000 ns/op, called 1-5x per request"
    echo "  - Classify: ~1,000-10,000 ns/op, called 1x per request"
    echo
    
    # Compute rough opportunity scores based on typical operations
    for bench_file in "${RUN_DIR}"/*.bench.txt; do
        if [[ ! -f "${bench_file}" ]]; then
            continue
        fi
        
        local name
        name=$(basename "${bench_file}" .bench.txt)
        
        
        grep '^Benchmark' "${bench_file}" | \
            awk -v name="${name}" '{
                bench=$1; 
                gsub(/^Benchmark/,"",bench); 
                gsub(/-[0-9]+$/,"",bench); 
                sum[bench]+=$3; 
                count[bench]++
            }
            END {
                for (b in sum) {
                    avg = sum[b]/count[b]
                    
                    # Estimate usage frequency based on benchmark name
                    freq = 1
                    if (b ~ /Scrub/ && name == "secret") {
                        freq = 5
                    } else if (b ~ /Chunk/ && name == "telemetry") {
                        freq = 2
                    } else if (b ~ /Classify/ && name == "responder") {
                        freq = 1
                    }
                    
                    # Opportunity score: (time in ms) * frequency
                    score = (avg / 1000000) * freq
                    
                    if (score >= 2.0) {
                        printf "  %-38s %10.2f ms * %d = %.2f (HIGH)\n", b, avg/1000000, freq, score
                    } else if (score >= 0.5) {
                        printf "  %-38s %10.2f ms * %d = %.2f\n", b, avg/1000000, freq, score
                    }
                }
            }' | sort -t= -k2 -n -r
        
        echo
        
        echo
    done
}

main
