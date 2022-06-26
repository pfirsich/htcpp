#!/bin/bash
set -eou pipefail # strict mode
commit_hash="$(git rev-parse HEAD)"
outdir="benchmarks/$commit_hash"
mkdir -p "$outdir"

concurrency="512"
duration="10s"
url="file/src/config.hpp"

HTCPP_ACCESS_LOG=0 build/htcpp --listen 127.0.0.1:6969 &
http_pid=$!

HTCPP_ACCESS_LOG=0 build/htcpp --listen 127.0.0.1:6970 --tls cert.pem key.pem &
https_pid=$!

echo "Warmup HTTP" # file cache, grow some buffers, allocate things
hey -c "$concurrency" -z 3s "http://localhost:6969/$url" > /dev/null

echo "http ${concurrency}"
outfile="$outdir/http_c${concurrency}_${duration}"
hey -c "$concurrency" -z "$duration" "http://localhost:6969/$url" > "$outfile"
grep "Requests/sec" "$outfile"

echo "http ${concurrency} close"
outfile="$outdir/http_c${concurrency}_${duration}_close"
hey -c "$concurrency" -z "$duration" -disable-keepalive "http://localhost:6969/$url" > "$outfile"
grep "Requests/sec" "$outfile"

echo "Warmup HTTPS"
hey -c "$concurrency" -z 3s "https://localhost:6970/$url" > /dev/null

echo "https ${concurrency}"
outfile="$outdir/https_c${concurrency}_${duration}"
hey -c "$concurrency" -z "$duration" "https://localhost:6970/$url" > "$outfile"
grep "Requests/sec" "$outfile"

echo "https ${concurrency} close"
outfile="$outdir/https_c${concurrency}_${duration}_close"
hey -c "$concurrency" -z "$duration" -disable-keepalive "https://localhost:6970/$url" > "$outfile"
grep "Requests/sec" "$outfile"

kill "$http_pid"
kill "$https_pid"
