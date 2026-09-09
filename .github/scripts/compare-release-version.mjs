#!/usr/bin/env node

function fail(message) {
  console.error(`::error::${message}`);
  process.exit(1);
}

function parseVersion(value, label) {
  const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(value);
  if (!match) {
    fail(`${label} '${value}' must use strict X.Y.Z format.`);
  }
  return match.slice(1).map(BigInt);
}

function compare(left, right) {
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] > right[index]) return 1;
    if (left[index] < right[index]) return -1;
  }
  return 0;
}

const [
  currentValue,
  candidateValue,
  mode = 'strict',
  allowDowngrade = 'false',
  downgradeReason = '',
] = process.argv.slice(2);

if (!currentValue || !candidateValue) {
  fail(
    'Usage: compare-release-version.mjs CURRENT CANDIDATE [strict|fallback] '
      + '[ALLOW_DOWNGRADE] [DOWNGRADE_REASON]',
  );
}
if (!['strict', 'fallback'].includes(mode)) {
  fail(`Unknown comparison mode '${mode}'.`);
}
if (!['true', 'false'].includes(allowDowngrade)) {
  fail('ALLOW_DOWNGRADE must be true or false.');
}

const current = parseVersion(currentValue, 'Current version');
const candidate = parseVersion(candidateValue, 'Candidate version');
const result = compare(candidate, current);

if (mode === 'strict' && result <= 0) {
  fail(
    `Candidate version ${candidateValue} must be newer than production version ${currentValue}.`,
  );
}

if (mode === 'fallback' && result < 0) {
  if (allowDowngrade !== 'true') {
    fail(
      `Candidate version ${candidateValue} is older than production version ${currentValue}; `
        + 'an explicit downgrade approval is required.',
    );
  }
  const auditReason = downgradeReason.trim().replace(/[\r\n]+/g, ' ');
  if (!auditReason) {
    fail('A non-empty downgrade reason is required.');
  }
  console.log(
    `::warning::Approved downgrade from ${currentValue} to ${candidateValue}: `
      + auditReason,
  );
} else {
  console.log(
    `Release-order check passed: production=${currentValue}, candidate=${candidateValue}.`,
  );
}
