/**
 * k6 performance test — POST /api/v1/keys/{keyId}/sign (warm path, sustained load).
 *
 * Placeholder for STG execution after merge. NOT executed in CI.
 *
 * Usage:
 *   k6 run sign-warm-stg.js \
 *     -e BASE_URL=https://wallet-ebw.stg.eudistack.net \
 *     -e BEARER_TOKEN=<holder-session-token> \
 *     -e KEY_ID=<uuid-from-key-generation>
 *
 * Thresholds (NFR-S-407-01 / NFR-S-407-02 / NFR-S-407-04):
 *   - http_req_duration p95 < 300 ms
 *   - http_req_duration p99 < 800 ms
 *   - throughput >= 30 RPS for 5 min
 *
 * Calibration note (ADR-025, AD-407-2):
 *   After this run, compare p50 of the warm signing path with the configured
 *   keymanager.sign.opaque-rejection-delay-millis value. The delay must be within
 *   ±20% of p50(sign_ok). Update the config and re-run OpaqueRejectionConstantTimeIT
 *   on STG if recalibration is needed.
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Counter } from 'k6/metrics';

const signDuration = new Trend('sign_duration', true);
const signErrors = new Counter('sign_errors');

export const options = {
  scenarios: {
    warm_sustained: {
      executor: 'constant-arrival-rate',
      rate: 30,
      timeUnit: '1s',
      duration: '5m',
      preAllocatedVUs: 10,
      maxVUs: 50,
    },
  },
  thresholds: {
    sign_duration: ['p(95)<300', 'p(99)<800'],
    sign_errors: ['count<10'],
  },
};

const BASE_URL = __ENV.BASE_URL || 'https://wallet-ebw.stg.eudistack.net';
const BEARER = __ENV.BEARER_TOKEN || '';
const KEY_ID = __ENV.KEY_ID || 'change-me';

// Minimal kb-jwt payload (sd_hash + nonce + aud + iat)
const SIGNING_INPUT = btoa(JSON.stringify({
  sd_hash: 'abc123def456',
  nonce: 'test-nonce-stg',
  aud: 'https://verifier.stg.eudistack.net',
  iat: Math.floor(Date.now() / 1000),
})).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

export default function () {
  const res = http.post(
    `${BASE_URL}/business-wallet/api/v1/keys/${KEY_ID}/sign`,
    JSON.stringify({
      signing_type: 'KB_JWT',
      purpose: 'PRESENTATION',
      signing_input: SIGNING_INPUT,
    }),
    {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${BEARER}`,
      },
    }
  );

  const ok = check(res, {
    'status is 200': (r) => r.status === 200,
    'jws present': (r) => r.json('jws') !== null,
  });

  signDuration.add(res.timings.duration);
  if (!ok) {
    signErrors.add(1);
  }

  sleep(0.01); // 10 ms jitter
}
