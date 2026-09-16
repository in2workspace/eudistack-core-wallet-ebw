#!/usr/bin/env bash
set -euo pipefail

for variable in CONTAINER_IMAGE CONTAINER_NAME DAST_DB_HOST DAST_DB_PORT \
  DAST_DB_NAME DAST_DB_USERNAME DAST_DB_PASSWORD; do
  if [[ -z "${!variable:-}" ]]; then
    echo "::error::Missing required DAST variable: ${variable}"
    exit 1
  fi
done

docker run -d --name "${CONTAINER_NAME}" \
  --network host \
  -e DB_HOST="${DAST_DB_HOST}" \
  -e DB_PORT="${DAST_DB_PORT}" \
  -e DB_NAME="${DAST_DB_NAME}" \
  -e DB_USERNAME="${DAST_DB_USERNAME}" \
  -e DB_PASSWORD="${DAST_DB_PASSWORD}" \
  -e TRUST_FORWARDED_HOST=true \
  "${CONTAINER_IMAGE}"

profile_table='sandbox_business_wallet.tenant_wallet_profile'
for _ in $(seq 1 60); do
  if PGPASSWORD="${DAST_DB_PASSWORD}" psql \
    --host "${DAST_DB_HOST}" \
    --port "${DAST_DB_PORT}" \
    --username "${DAST_DB_USERNAME}" \
    --dbname "${DAST_DB_NAME}" \
    --tuples-only \
    --no-align \
    --command "SELECT to_regclass('${profile_table}') IS NOT NULL" 2>/dev/null |
      grep --quiet '^t$'; then
    PGPASSWORD="${DAST_DB_PASSWORD}" psql \
      --host "${DAST_DB_HOST}" \
      --port "${DAST_DB_PORT}" \
      --username "${DAST_DB_USERNAME}" \
      --dbname "${DAST_DB_NAME}" \
      --set ON_ERROR_STOP=1 \
      --command "
        INSERT INTO ${profile_table} (tenant, wallet_mode, key_manager)
        VALUES ('sandbox', 'browser', NULL)
        ON CONFLICT (tenant) DO UPDATE SET
          wallet_mode = EXCLUDED.wallet_mode,
          key_manager = EXCLUDED.key_manager,
          updated_at = now();
      "
    exit 0
  fi

  if [[ "$(docker inspect --format '{{.State.Running}}' "${CONTAINER_NAME}")" != "true" ]]; then
    echo "::error::DAST container stopped before tenant migrations completed."
    docker logs "${CONTAINER_NAME}"
    exit 1
  fi
  sleep 2
done

echo "::error::Timed out waiting for ${profile_table}."
docker logs "${CONTAINER_NAME}"
exit 1
