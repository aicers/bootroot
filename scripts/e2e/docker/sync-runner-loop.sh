#!/usr/bin/env bash
set -euo pipefail

INTERVAL_SECS="${INTERVAL_SECS:-5}"
MAX_CYCLES="${MAX_CYCLES:-0}"
RUNNER_LOG="${RUNNER_LOG:-}"
SCENARIO_ID="${SCENARIO_ID:-docker-harness-smoke}"
NODE_ID="${NODE_ID:-service-node-01}"
SERVICE_ID="${SERVICE_ID:-edge-proxy}"
SYNC_COMMAND="${SYNC_COMMAND:-}"

if [ -z "$SYNC_COMMAND" ]; then
  printf "SYNC_COMMAND is required\n" >&2
  exit 1
fi

cycle=0
while true; do
  cycle=$((cycle + 1))
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [ -n "$RUNNER_LOG" ]; then
    printf '{"ts":"%s","phase":"sync-loop","scenario":"%s","node":"%s","service":"%s","cycle":%d}\n' \
      "$now" "$SCENARIO_ID" "$NODE_ID" "$SERVICE_ID" "$cycle" >>"$RUNNER_LOG"
  fi

  if ! /bin/sh -c "$SYNC_COMMAND"; then
    if [ -n "$RUNNER_LOG" ]; then
      printf '{"ts":"%s","phase":"sync-loop-error","scenario":"%s","node":"%s","service":"%s","cycle":%d}\n' \
        "$now" "$SCENARIO_ID" "$NODE_ID" "$SERVICE_ID" "$cycle" >>"$RUNNER_LOG"
    fi
    exit 1
  fi

  if [ "$MAX_CYCLES" -gt 0 ] && [ "$cycle" -ge "$MAX_CYCLES" ]; then
    break
  fi
  sleep "$INTERVAL_SECS"
done
