/**
 * k6 performance test — POST /api/v1/keys/{keyId}/sign (burst load).
 *
 * Placeholder for STG execution after merge. NOT executed in CI.
 *
 * Usage:
 *   k6 run sign-burst-stg.js \
 *     -e BASE_URL=https://wallet-ebw.stg.eudistack.net \
 *     -e BEARER_TOKEN=<holder-session-token> \
 *     -e KEY_ID=<uuid-from-key-generation>
 *
 * Thresholds (NFR-S-407-04):
 *   - sustained throughput >= 30 RPS for the burst window
 *   - no 503 responses (timeout kill-switch must not fire under normal burst load)
 */

import http from 'k6/http';
import { check } from 'k6';
import { Trend, Counter } from 'k6/metrics';

const signDuration = new Trend('sign_duration', true);
const signTimeouts = new Counter('sign_timeouts');

export const options = {
  scenarios: {
    burst: {
      executor: 'ramping-arrival-rate',
      startRate: 10,
      timeUnit: '1s',
      stages: [
        { target: 50, duration: '30s' },
        { target: 50, duration: '2m' },
        { target: 10, duration: '30s' },
      ],
      preAllocatedVUs: 20,
      maxVUs: 100,
    },
  },
  thresholds: {
    sign_duration: ['p(95)<300'],
    sign_timeouts: ['count<1'],
  },
};

const BASE_URL = __ENV.BASE_URL || 'https://wallet-ebw.stg.eudistack.net';
const BEARER = __ENV.BEARER_TOKEN || '';
const KEY_ID = __ENV.KEY_ID || 'change-me';

const SIGNING_INPUT = btoa(JSON.stringify({
  sd_hash: 'burst-hash',
  nonce: 'burst-nonce',
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
  });

  signDuration.add(res.timings.duration);
  if (res.status === 503) {
    signTimeouts.add(1);
  }
}
