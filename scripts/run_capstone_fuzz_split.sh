#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 0 ]]; then
  echo "usage: $0" >&2
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/build/decode_capstone_fuzz_full32_test"

if [[ ! -x "${BIN}" ]]; then
  echo "error: ${BIN} not found or not executable; build first" >&2
  exit 2
fi

LOG_DIR="${ROOT_DIR}/build/fuzz-logs"
mkdir -p "${LOG_DIR}"

TOTAL=4294967296
THREADS=16
CHUNK=$((TOTAL / THREADS))
PIDS=()
LOGS=()

for i in $(seq 0 $((THREADS - 1))); do
  START=$((i * CHUNK))
  END=$((START + CHUNK - 1))
  LOG="${LOG_DIR}/fuzz_${i}.log"
  LOGS+=("${LOG}")
  "${BIN}" --start "${START}" --end "${END}" >"${LOG}" 2>&1 &
  PIDS+=($!)
done

status=0
for idx in "${!PIDS[@]}"; do
  pid="${PIDS[$idx]}"
  if ! wait "${pid}"; then
    status=1
  fi
done

if [[ "${status}" -ne 0 ]]; then
  echo "fuzz failed; logs in ${LOG_DIR}" >&2
  exit 1
fi

echo "fuzz succeeded; logs in ${LOG_DIR}"
exit 0
