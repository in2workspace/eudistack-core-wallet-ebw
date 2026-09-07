#!/usr/bin/env bash
set -euo pipefail

readiness_url="${1:?readiness URL is required}"

for attempt in $(seq 1 30); do
  if curl --fail --silent --show-error \
    --connect-timeout 5 \
    --max-time 15 \
    "${readiness_url}" > /dev/null; then
    echo "Readiness check passed: ${readiness_url}"
    exit 0
  fi
  echo "Readiness attempt ${attempt}/30 failed; retrying in 10 seconds."
  sleep 10
done

echo "::error::Service did not become ready at ${readiness_url}."
exit 1
