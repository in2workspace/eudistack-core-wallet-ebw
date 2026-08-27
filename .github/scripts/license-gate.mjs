#!/usr/bin/env node
/**
 * License Gate — CycloneDX SBOM license compliance evaluator.
 *
 * Self-contained: zero third-party dependencies, runs on the Node.js already
 * present on GitHub-hosted runners. This file is VENDORED into every repository
 * under `.github/scripts/license-gate.mjs`; it is never consumed across
 * repositories. The reference copy lives in `eudistack-platform-dev` under
 * `templates/license-gate/` — see `docs/_shared/guides/license-gate-and-sbom.md`.
 *
 * Policy source of truth: `conv-quality-security-gates.md` §16.1, transcribed
 * into the repository-local `.github/license-policy.json` and protected by
 * `.github/CODEOWNERS`.
 *
 * Usage:
 *   node .github/scripts/license-gate.mjs --sbom-path build/reports/sbom/sbom.json
 *   node .github/scripts/license-gate.mjs --sbom-path <path> --expect-version 1.4.0
 *
 * Exit codes: 0 = compliant, 1 = blocking violation or execution error.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const MAX_EXCEPTION_DAYS = 180;
const NEAR_EXPIRY_THRESHOLD_DAYS = 30;

// ---------------------------------------------------------------------------
// License name normalization (EC-03)
// ---------------------------------------------------------------------------

/**
 * Free-text license names, as emitted by upstream POM/package metadata, mapped
 * to the SPDX expression they actually represent.
 *
 * Every entry is a deliberate, auditable equivalence — never an inference. A
 * name that is not listed here stays `UNNORMALIZED_LICENSE` and blocks, which
 * is the safe default: it forces either a new reviewed entry in this table or
 * an approved exception. Because the table lives in the repository, changing it
 * goes through `CODEOWNERS` exactly like the policy itself.
 *
 * Comma-separated upstream names are disjunctions in every case below (the
 * component is multi-licensed and the consumer chooses), so they normalize to
 * `A OR B`. Never assume this for a name that is not in the table.
 */
export const LICENSE_NAME_NORMALIZATION = {
  // Public domain dedications — no obligations attach.
  'public domain': 'LicenseRef-PublicDomain',
  'cc0 universal': 'CC0-1.0',
  'cc0 1.0 universal': 'CC0-1.0',

  // Apache
  'apache 2.0': 'Apache-2.0',
  'apache 2': 'Apache-2.0',
  'apache license 2.0': 'Apache-2.0',
  'apache license, version 2.0': 'Apache-2.0',
  'the apache license, version 2.0': 'Apache-2.0',
  'the apache software license, version 2.0': 'Apache-2.0',
  'al 2.0': 'Apache-2.0',

  // MIT and equivalents. The Bouncy Castle Licence is a verbatim copy of the
  // MIT license text (see https://www.bouncycastle.org/licence.html).
  'mit license': 'MIT',
  'the mit license': 'MIT',
  'the mit license (mit)': 'MIT',
  'bouncy castle licence': 'MIT',
  'bouncy castle license': 'MIT',

  // BSD
  'the bsd 3-clause license': 'BSD-3-Clause',
  'bsd 3-clause license': 'BSD-3-Clause',
  'the bsd 2-clause license': 'BSD-2-Clause',
  'bsd 2-clause license': 'BSD-2-Clause',

  // Eclipse
  'eclipse public license 2.0': 'EPL-2.0',
  'eclipse public license - v 2.0': 'EPL-2.0',
  'eclipse public license v2.0': 'EPL-2.0',
  'eclipse public license 1.0': 'EPL-1.0',
  'eclipse public license - v 1.0': 'EPL-1.0',

  // ISC / other permissive
  'isc license': 'ISC',
  'the unlicense': 'Unlicense',

  // Multi-licensed components declared as free text. All are disjunctions.
  'epl-1.0, gnu lesser general public license': 'EPL-1.0 OR LGPL-2.1',
  'epl-2.0, gnu lesser general public license': 'EPL-2.0 OR LGPL-2.1',
  'epl-2.0, gpl-2.0-with-classpath-exception': 'EPL-2.0 OR GPL-2.0-with-classpath-exception',
  'epl-2.0, gpl-2.0-with-classpath-exception, bsd-3-clause': 'EPL-2.0 OR GPL-2.0-with-classpath-exception OR BSD-3-Clause',
  'cc0-1.0, bsd-2-clause': 'CC0-1.0 OR BSD-2-Clause',
  'al 2.0, gpl v2, mpl-2.0': 'Apache-2.0 OR GPL-2.0-only OR MPL-2.0'
};

/**
 * Canonicalizes a free-text license name for table lookup: lowercase, collapsed
 * whitespace, no surrounding punctuation.
 *
 * @param {string} name
 * @returns {string}
 */
export function canonicalizeLicenseName(name) {
  if (!name || typeof name !== 'string') return '';
  return name.trim().toLowerCase().replace(/\s+/g, ' ').replace(/^[."'\s]+|[."'\s]+$/g, '');
}

/**
 * Resolves a free-text license name to its SPDX expression, if a reviewed
 * equivalence exists.
 *
 * @param {string} name
 * @returns {string|null} SPDX expression, or null when the name is unknown.
 */
export function normalizeLicenseName(name) {
  const key = canonicalizeLicenseName(name);
  return Object.prototype.hasOwnProperty.call(LICENSE_NAME_NORMALIZATION, key)
    ? LICENSE_NAME_NORMALIZATION[key]
    : null;
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/**
 * Loads and validates the repository-local license policy.
 *
 * @param {string} policyPath
 * @returns {{ allow: string[], gatedScopes: string[] }}
 * @throws {Error} When the file is missing, malformed, or declares no licenses.
 */
export function loadPolicy(policyPath) {
  if (!policyPath) {
    throw new Error('Policy path must be specified');
  }

  const resolvedPath = path.resolve(process.cwd(), policyPath);
  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Policy file '${policyPath}' does not exist (ES-01)`);
  }

  const content = fs.readFileSync(resolvedPath, 'utf8');
  if (!content.trim()) {
    throw new Error(`Policy file '${policyPath}' is empty (ES-01)`);
  }

  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch (err) {
    throw new Error(`Policy file '${policyPath}' is malformed JSON: ${err.message} (ES-01)`);
  }

  const allow = Array.isArray(parsed) ? parsed : parsed?.allow;
  if (!Array.isArray(allow)) {
    throw new Error(`Policy file '${policyPath}' must contain an 'allow' array (ES-01)`);
  }
  if (allow.length === 0) {
    throw new Error(`Policy file '${policyPath}' has an empty allow list (ES-01)`);
  }
  for (const item of allow) {
    if (typeof item !== 'string' || !item.trim()) {
      throw new Error(`Policy file '${policyPath}' contains an invalid license identifier: ${JSON.stringify(item)} (ES-01)`);
    }
  }

  return {
    allow: allow.map(id => id.trim()),
    gatedScopes: Array.isArray(parsed?.gatedScopes) ? parsed.gatedScopes : ['runtime']
  };
}

// ---------------------------------------------------------------------------
// SBOM
// ---------------------------------------------------------------------------

/**
 * Loads and parses a CycloneDX JSON SBOM.
 *
 * @param {string} sbomPath
 * @returns {object}
 * @throws {Error} When the file is missing, malformed, or has no components.
 */
export function loadSbom(sbomPath) {
  if (!sbomPath) {
    throw new Error('SBOM path must be specified');
  }

  const resolvedPath = path.resolve(process.cwd(), sbomPath);
  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`SBOM file '${sbomPath}' does not exist (ES-02)`);
  }

  const content = fs.readFileSync(resolvedPath, 'utf8');
  if (!content.trim()) {
    throw new Error(`SBOM file '${sbomPath}' is empty (ES-02)`);
  }

  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch (err) {
    throw new Error(`SBOM file '${sbomPath}' is malformed JSON: ${err.message} (ES-02)`);
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new Error(`SBOM file '${sbomPath}' must be a JSON object (ES-02)`);
  }
  if (!Array.isArray(parsed.components) || parsed.components.length === 0) {
    throw new Error(`SBOM file '${sbomPath}' contains no components (EC-08)`);
  }

  return parsed;
}

/**
 * Parses an SPDX expression into an evaluable entry.
 *
 * Only pure disjunctions are interpreted. Conjunctions (`AND`), exception
 * clauses (`WITH`), `+` suffixes and nested parentheses block as
 * `UNPARSEABLE_EXPRESSION`: under `AND` every term binds, so a single blocked
 * term taints the component, and interpreting that automatically is precisely
 * the judgement call the gate must not make on its own (EC-01).
 *
 * @param {string} rawExpression
 * @returns {object} Entry describing the expression.
 */
export function parseSpdxExpression(rawExpression) {
  const raw = String(rawExpression).trim();
  const clean = raw.replace(/^\s*\(\s*/, '').replace(/\s*\)\s*$/, '').trim();

  // Operators are matched whitespace-delimited, not with \b: a word boundary
  // also lands on the hyphens of an identifier, so `\bWITH\b` fires inside
  // `GPL-2.0-with-classpath-exception` and would block a perfectly ordinary
  // disjunction as unparseable.
  const hasOr = /\s+OR\s+/i.test(clean);
  const hasAnd = /\s+AND\s+/i.test(clean);
  const hasWith = /\s+WITH\s+/i.test(clean);
  const hasPlus = clean.includes('+');
  const hasInnerParens = /[()]/.test(clean);

  if (!hasOr && !hasAnd && !hasWith && !hasPlus && !hasInnerParens) {
    return { type: 'SPDX_ID', id: clean, display: raw };
  }

  if (hasOr && !hasAnd && !hasWith && !hasPlus && !hasInnerParens) {
    const terms = clean.split(/\s+OR\s+/i).map(t => t.trim()).filter(Boolean);
    return { type: 'EXPRESSION_OR', expression: raw, terms, display: raw };
  }

  return { type: 'UNPARSEABLE_EXPRESSION', expression: raw, display: raw };
}

/**
 * Resolves the licenses declared by a CycloneDX component, normalizing
 * free-text names against the reviewed equivalence table.
 *
 * @param {object} component
 * @returns {{ status: string, display: string, entries: object[], details?: object }}
 */
export function resolveDeclaredLicenses(component) {
  const declared = component?.licenses;
  if (!Array.isArray(declared) || declared.length === 0) {
    return { status: 'NO_LICENSE', display: '(none)', entries: [] };
  }

  const entries = [];

  for (const item of declared) {
    if (typeof item?.expression === 'string' && item.expression.trim()) {
      entries.push(parseSpdxExpression(item.expression));
      continue;
    }

    const license = item?.license;
    if (license && typeof license === 'object') {
      if (typeof license.id === 'string' && license.id.trim()) {
        const id = license.id.trim();
        entries.push({ type: 'SPDX_ID', id, display: id });
        continue;
      }
      if (typeof license.name === 'string' && license.name.trim()) {
        const name = license.name.trim();
        const normalized = normalizeLicenseName(name);
        if (normalized) {
          const entry = parseSpdxExpression(normalized);
          entries.push({ ...entry, display: `${name} → ${normalized}`, normalizedFrom: name });
        } else {
          entries.push({ type: 'UNNORMALIZED_LICENSE', name, display: name });
        }
        continue;
      }
    }

    entries.push({ type: 'NO_LICENSE', display: '(none)' });
  }

  if (entries.length === 1) {
    const single = entries[0];
    return { status: single.type, display: single.display, details: single, entries };
  }

  return { status: 'MULTI_LICENSE', display: entries.map(e => e.display).join(', '), entries };
}

/**
 * Decides whether a single resolved entry satisfies the allowlist.
 *
 * @param {object} entry
 * @param {Set<string>} allowedSet
 * @returns {{ allowed: boolean, detail: string }}
 */
function evaluateEntry(entry, allowedSet) {
  if (entry.type === 'SPDX_ID') {
    return allowedSet.has(entry.id)
      ? { allowed: true, detail: `'${entry.id}' is in the allowlist` }
      : { allowed: false, detail: `'${entry.id}' is outside the allowlist (FR-10, AC-06)` };
  }

  if (entry.type === 'EXPRESSION_OR') {
    const allowedTerm = entry.terms.find(t => allowedSet.has(t));
    return allowedTerm
      ? { allowed: true, detail: `allowed via disjunction option '${allowedTerm}'` }
      : { allowed: false, detail: `no term of '${entry.expression}' is in the allowlist` };
  }

  if (entry.type === 'UNNORMALIZED_LICENSE') {
    return {
      allowed: false,
      detail: `'${entry.name}' is free text with no reviewed SPDX equivalence — add it to LICENSE_NAME_NORMALIZATION or register an exception (EC-03)`
    };
  }

  if (entry.type === 'UNPARSEABLE_EXPRESSION') {
    return {
      allowed: false,
      detail: `compound expression '${entry.expression}' cannot be interpreted with certainty (EC-01)`
    };
  }

  return { allowed: false, detail: 'component declares no license (FR-11)' };
}

/**
 * Evaluates a component against the allowlist.
 *
 * Every independent license entry must be satisfied: multiple entries in the
 * CycloneDX `licenses` array are cumulative obligations, unlike the terms of a
 * single `OR` expression (EC-02).
 *
 * @param {object} component
 * @param {Set<string>|string[]} allowedLicenses
 * @returns {{ allowed: boolean, status: string, declaredLicense: string, reason: string }}
 */
export function evaluateComponentLicenses(component, allowedLicenses) {
  const allowedSet = allowedLicenses instanceof Set ? allowedLicenses : new Set(allowedLicenses);
  const resolved = resolveDeclaredLicenses(component);

  if (resolved.status === 'NO_LICENSE') {
    return {
      allowed: false,
      status: 'NO_LICENSE',
      declaredLicense: '(none)',
      reason: 'Component declares no license, so no rights are granted to distribute it (FR-11)'
    };
  }

  const failures = [];
  for (const entry of resolved.entries) {
    const verdict = evaluateEntry(entry, allowedSet);
    if (!verdict.allowed) failures.push(verdict.detail);
  }

  if (failures.length === 0) {
    return {
      allowed: true,
      status: 'ALLOWED',
      declaredLicense: resolved.display,
      reason: 'All declared licenses are in the allowlist'
    };
  }

  const status = resolved.entries.length === 1 && resolved.entries[0].type !== 'SPDX_ID' && resolved.entries[0].type !== 'EXPRESSION_OR'
    ? resolved.entries[0].type
    : 'BLOCKED_LICENSE';

  return {
    allowed: false,
    status,
    declaredLicense: resolved.display,
    reason: failures.join('; ')
  };
}

/**
 * Splits SBOM components into what is distributed at runtime and what only
 * serves to build or test, and drops the repository's own artifact (EC-09).
 *
 * @param {object} sbom
 * @param {string[]} [gatedScopes=['runtime']]
 * @returns {{ runtimeComponents: object[], devTestComponents: object[], selfComponent: object|null }}
 */
export function selectGatedComponents(sbom, gatedScopes = ['runtime']) {
  if (!sbom || !Array.isArray(sbom.components)) {
    return { runtimeComponents: [], devTestComponents: [], selfComponent: null };
  }

  const selfPurl = sbom.metadata?.component?.purl;
  const scopes = (Array.isArray(gatedScopes) ? gatedScopes : [gatedScopes]).filter(Boolean);
  const gateAll = scopes.includes('all');

  const runtimeComponents = [];
  const devTestComponents = [];
  let selfComponent = null;

  for (const comp of sbom.components) {
    if (selfPurl && comp.purl === selfPurl) {
      selfComponent = comp;
      continue;
    }

    const devByScope = comp.scope === 'excluded' || comp.scope === 'optional';
    const devByProperty = Array.isArray(comp.properties) && comp.properties.some(p =>
      (p.name === 'cdx:npm:package:development' && p.value === 'true') ||
      (p.name === 'development' && p.value === 'true')
    );

    if (!gateAll && (devByScope || devByProperty)) {
      devTestComponents.push(comp);
    } else {
      runtimeComponents.push(comp);
    }
  }

  return { runtimeComponents, devTestComponents, selfComponent };
}

/**
 * Asserts the SBOM describes the version being released (ES-03).
 *
 * @param {object} sbom
 * @param {string} [expectVersion]
 * @returns {boolean}
 * @throws {Error} When the versions differ.
 */
export function assertSbomVersionMatches(sbom, expectVersion) {
  if (!expectVersion) return true;

  const sbomVersion = sbom.metadata?.component?.version;
  if (!sbomVersion) {
    throw new Error(`SBOM metadata declares no component version, but version '${expectVersion}' was expected (ES-03)`);
  }

  const expected = expectVersion.trim().replace(/^v/, '');
  const actual = sbomVersion.trim().replace(/^v/, '');
  if (expected !== actual) {
    throw new Error(`SBOM component version '${sbomVersion}' does not match the release version '${expectVersion}' (ES-03)`);
  }

  return true;
}

// ---------------------------------------------------------------------------
// Exceptions
// ---------------------------------------------------------------------------

/**
 * Strips qualifiers and subpath from a PURL.
 *
 * @param {string} purl
 * @returns {string}
 */
export function normalizePurl(purl) {
  if (!purl || typeof purl !== 'string') return '';
  return purl.split('?')[0].split('#')[0];
}

/**
 * Returns a PURL without its version, so exceptions can be detected as bound to
 * a different version of the same package.
 *
 * @param {string} purl
 * @returns {string}
 */
export function getPurlPackageBase(purl) {
  const normalized = normalizePurl(purl);
  const at = normalized.lastIndexOf('@');
  return at !== -1 ? normalized.slice(0, at) : normalized;
}

/**
 * Validates one exception record.
 *
 * @param {object} record
 * @param {string} [filePath]
 * @returns {boolean}
 * @throws {Error} When a field is missing or the exception outlives the cap.
 */
export function validateExceptionRecord(record, filePath = '.github/license-exceptions.json') {
  if (!record || typeof record !== 'object') {
    throw new Error(`Exception record in '${filePath}' must be an object`);
  }

  for (const field of ['purl', 'license', 'reason', 'approved_by', 'approved_on', 'expires_on', 'ticket']) {
    if (typeof record[field] !== 'string' || !record[field].trim()) {
      throw new Error(`Exception record in '${filePath}' is missing required field '${field}': ${JSON.stringify(record)} (NFR-S-220-05)`);
    }
  }

  if (!record.purl.includes('@')) {
    throw new Error(`Exception purl '${record.purl}' in '${filePath}' must pin a version (EC-06)`);
  }

  const approved = new Date(record.approved_on);
  const expires = new Date(record.expires_on);
  if (Number.isNaN(approved.getTime())) {
    throw new Error(`Invalid 'approved_on' in '${filePath}': '${record.approved_on}' (expected YYYY-MM-DD)`);
  }
  if (Number.isNaN(expires.getTime())) {
    throw new Error(`Invalid 'expires_on' in '${filePath}': '${record.expires_on}' (expected YYYY-MM-DD)`);
  }
  if (expires <= approved) {
    throw new Error(`'expires_on' (${record.expires_on}) must be after 'approved_on' (${record.approved_on}) in '${filePath}' for ${record.purl}`);
  }

  const days = (expires.getTime() - approved.getTime()) / 86400000;
  if (days > MAX_EXCEPTION_DAYS) {
    throw new Error(`Exception for '${record.purl}' in '${filePath}' lasts ${Math.round(days)} days, over the ${MAX_EXCEPTION_DAYS}-day cap (NFR-S-220-05)`);
  }

  return true;
}

/**
 * Loads approved exceptions. A missing file means "no exceptions", which is the
 * expected steady state.
 *
 * @param {string} exceptionsPath
 * @returns {object[]}
 */
export function loadExceptions(exceptionsPath) {
  if (!exceptionsPath) return [];

  const resolvedPath = path.resolve(process.cwd(), exceptionsPath);
  if (!fs.existsSync(resolvedPath)) return [];

  const content = fs.readFileSync(resolvedPath, 'utf8');
  if (!content.trim()) return [];

  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch (err) {
    throw new Error(`Exceptions file '${exceptionsPath}' is malformed JSON: ${err.message} (ES-01)`);
  }

  const list = Array.isArray(parsed) ? parsed : (Array.isArray(parsed?.exceptions) ? parsed.exceptions : []);
  for (const record of list) {
    validateExceptionRecord(record, exceptionsPath);
  }

  return list;
}

/**
 * Finds a live approved exception for a component.
 *
 * @param {object[]} exceptions
 * @param {string} componentPurl
 * @param {Date} [now=new Date()]
 * @returns {object} Match outcome.
 */
export function findApprovedException(exceptions, componentPurl, now = new Date()) {
  if (!Array.isArray(exceptions) || exceptions.length === 0 || !componentPurl) {
    return { matched: false, reason: 'NO_EXCEPTION' };
  }

  const target = normalizePurl(componentPurl);
  const exact = exceptions.find(e => normalizePurl(e.purl) === target);

  if (exact) {
    const expires = new Date(exact.expires_on);
    expires.setHours(23, 59, 59, 999);

    if (now.getTime() > expires.getTime()) {
      return { matched: false, exception: exact, reason: 'EXCEPTION_EXPIRED', expiresOn: exact.expires_on };
    }

    const daysRemaining = Math.max(0, Math.ceil((expires.getTime() - now.getTime()) / 86400000));
    return { matched: true, exception: exact, daysRemaining, nearExpiry: daysRemaining <= NEAR_EXPIRY_THRESHOLD_DAYS };
  }

  const otherVersion = exceptions.find(e => getPurlPackageBase(e.purl) === getPurlPackageBase(componentPurl));
  if (otherVersion) {
    return { matched: false, reason: 'EXCEPTION_OTHER_VERSION', existingException: otherVersion };
  }

  return { matched: false, reason: 'NO_EXCEPTION' };
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

/**
 * Formats a GitHub Actions annotation.
 *
 * @param {'error'|'warning'|'notice'} type
 * @param {string} message
 * @param {object} [options={}]
 * @returns {string}
 */
export function formatAnnotation(type, message, options = {}) {
  const pairs = Object.entries(options)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `${k}=${v}`);
  const suffix = pairs.length ? ` ${pairs.join(',')}` : '';
  return `::${type}${suffix}::${message.replace(/\r?\n/g, '%0A')}`;
}

/**
 * Builds the Markdown job summary.
 *
 * @param {object} results
 * @param {object} [meta={}]
 * @returns {string}
 */
export function buildStepSummary(results, meta = {}) {
  const { totalScanned = 0, runtimeCount = 0, devTestCount = 0, allowedCount = 0,
    violations = [], warnings = [], approvedExceptions = [] } = results;

  const lines = [
    `# License Gate: ${violations.length === 0 ? '✅ PASSED' : '❌ FAILED'}`,
    '',
    `**SBOM:** \`${meta.sbomPath || 'sbom.json'}\` · **Policy:** \`${meta.policyPath || '.github/license-policy.json'}\``,
    '',
    '| Metric | Count |',
    '| --- | --- |',
    `| Components in SBOM | ${totalScanned} |`,
    `| Runtime components evaluated | ${runtimeCount} |`,
    `| Build/test components (not distributed) | ${devTestCount} |`,
    `| Compliant with the allowlist | ${allowedCount} |`,
    `| Approved exceptions applied | ${approvedExceptions.length} |`,
    `| Blocking violations | ${violations.length} |`,
    `| Warnings | ${warnings.length} |`,
    ''
  ];

  if (violations.length > 0) {
    lines.push('### Blocking violations', '',
      '| Component | Version | Declared license | Status | Reason |',
      '| --- | --- | --- | --- | --- |');
    for (const v of violations) {
      lines.push(`| \`${v.component?.name ?? 'unknown'}\` | \`${v.component?.version ?? '?'}\` | ${v.declaredLicense} | \`${v.status}\` | ${v.reason} |`);
    }
    lines.push('',
      'Resolve by replacing the component, or by registering an approved exception in `.github/license-exceptions.json` with justification, ticket and expiry date. See `docs/_shared/guides/license-gate-and-sbom.md`.',
      '');
  }

  if (approvedExceptions.length > 0) {
    lines.push('### Approved exceptions applied', '',
      '| Component | License | Ticket | Approved by | Expires |',
      '| --- | --- | --- | --- | --- |');
    for (const e of approvedExceptions) {
      const expiry = e.nearExpiry ? `${e.exception.expires_on} ⚠️ ${e.daysRemaining} d` : e.exception.expires_on;
      lines.push(`| \`${e.component?.name ?? 'unknown'}\` | ${e.exception.license} | ${e.exception.ticket} | ${e.exception.approved_by} | ${expiry} |`);
    }
    lines.push('');
  }

  if (warnings.length > 0) {
    lines.push('### Warnings (non-blocking)', '', '| Component | Message |', '| --- | --- |');
    for (const w of warnings) {
      lines.push(`| \`${w.component?.name ?? 'unknown'}\` | ${w.message} |`);
    }
    lines.push('');
  }

  lines.push('---', '*Policy: `conv-quality-security-gates.md` §16.1 · Story `EUD-220`.*', '');
  return lines.join('\n');
}

/**
 * Emits annotations and appends the job summary.
 *
 * @param {object} results
 * @param {object} [meta={}]
 * @returns {{ annotations: string[], summary: string }}
 */
export function generateReport(results, meta = {}) {
  const exceptionsPath = meta.exceptionsPath || '.github/license-exceptions.json';
  const annotations = [];

  for (const v of results.violations || []) {
    const name = v.component?.name ?? 'unknown';
    const version = v.component?.version ?? '?';
    annotations.push(formatAnnotation('error',
      `License Gate: '${name}@${version}' (${v.component?.purl ?? ''}) declares '${v.declaredLicense}' — ${v.reason}. `
      + `Replace the component, or register an approved exception in ${exceptionsPath}.`,
      { file: meta.sbomPath }));
  }

  for (const w of results.warnings || []) {
    annotations.push(formatAnnotation('warning', w.message,
      { file: w.type === 'NEAR_EXPIRY' ? exceptionsPath : meta.sbomPath }));
  }

  const summary = buildStepSummary(results, meta);
  const summaryFile = meta.summaryPath || process.env.GITHUB_STEP_SUMMARY;
  if (summaryFile) {
    try {
      fs.appendFileSync(summaryFile, `${summary}\n`, 'utf8');
    } catch (err) {
      console.warn(`[license-gate] could not write the job summary: ${err.message}`);
    }
  }

  return { annotations, summary };
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

/**
 * Parses CLI arguments.
 *
 * @param {string[]} argv
 * @returns {object}
 */
export function parseArgs(argv) {
  const options = {
    sbomPath: '',
    policyPath: '.github/license-policy.json',
    exceptionsPath: '.github/license-exceptions.json',
    gatedScopes: ['runtime'],
    expectVersion: undefined,
    refDate: process.env.LICENSE_GATE_REF_DATE ? new Date(process.env.LICENSE_GATE_REF_DATE) : new Date()
  };

  for (let i = 0; i < argv.length; i++) {
    let flag = argv[i];
    let value = '';

    if (flag.includes('=')) {
      const eq = flag.indexOf('=');
      value = flag.slice(eq + 1);
      flag = flag.slice(0, eq);
    } else if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) {
      value = argv[++i];
    }

    switch (flag) {
      case '--sbom-path': options.sbomPath = value; break;
      case '--policy-path': options.policyPath = value; break;
      case '--exceptions-path': options.exceptionsPath = value; break;
      case '--gated-scopes': options.gatedScopes = value.split(',').map(s => s.trim()); break;
      case '--expect-version': options.expectVersion = value; break;
      case '--ref-date': options.refDate = new Date(value); break;
      default: break;
    }
  }

  return options;
}

/**
 * Runs the whole gate: load, select, evaluate, report.
 *
 * @param {object} options
 * @returns {{ success: boolean, results: object, report: object }}
 */
export function runLicenseGate(options) {
  if (!options.sbomPath) {
    throw new Error('Missing required argument: --sbom-path');
  }

  const policy = loadPolicy(options.policyPath);
  const sbom = loadSbom(options.sbomPath);
  assertSbomVersionMatches(sbom, options.expectVersion);
  const exceptions = loadExceptions(options.exceptionsPath);

  const { runtimeComponents, devTestComponents } = selectGatedComponents(sbom, options.gatedScopes);
  const allowedSet = new Set(policy.allow);

  const violations = [];
  const warnings = [];
  const approvedExceptions = [];
  let allowedCount = 0;

  for (const component of runtimeComponents) {
    const verdict = evaluateComponentLicenses(component, allowedSet);

    if (verdict.allowed) {
      allowedCount++;
      continue;
    }

    const exception = findApprovedException(exceptions, component.purl, options.refDate);

    if (exception.matched) {
      approvedExceptions.push({ component, exception: exception.exception, daysRemaining: exception.daysRemaining, nearExpiry: exception.nearExpiry });
      if (exception.nearExpiry) {
        warnings.push({
          type: 'NEAR_EXPIRY',
          component,
          message: `The approved exception for '${component.name}@${component.version}' expires on ${exception.exception.expires_on} (${exception.daysRemaining} days left) — ticket ${exception.exception.ticket} (EC-05)`
        });
      }
      continue;
    }

    if (exception.reason === 'EXCEPTION_EXPIRED') {
      violations.push({ component, status: 'EXCEPTION_EXPIRED', declaredLicense: verdict.declaredLicense, reason: `the approved exception expired on ${exception.expiresOn} (EC-05)` });
    } else if (exception.reason === 'EXCEPTION_OTHER_VERSION') {
      violations.push({ component, status: 'EXCEPTION_OTHER_VERSION', declaredLicense: verdict.declaredLicense, reason: `the approved exception covers '${exception.existingException.purl}', not this version (EC-06)` });
    } else {
      violations.push({ component, status: verdict.status, declaredLicense: verdict.declaredLicense, reason: verdict.reason });
    }
  }

  for (const component of devTestComponents) {
    const verdict = evaluateComponentLicenses(component, allowedSet);
    if (!verdict.allowed) {
      warnings.push({
        type: 'DEV_TEST_UNALLOWED',
        component,
        message: `'${component.name}@${component.version}' declares '${verdict.declaredLicense}', outside the allowlist, but only serves to build or test and is not distributed (EC-04)`
      });
    }
  }

  const results = {
    totalScanned: sbom.components.length,
    runtimeCount: runtimeComponents.length,
    devTestCount: devTestComponents.length,
    allowedCount,
    violations,
    warnings,
    approvedExceptions
  };

  return {
    success: violations.length === 0,
    results,
    report: generateReport(results, options)
  };
}

const isCli = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));

if (isCli) {
  try {
    const outcome = runLicenseGate(parseArgs(process.argv.slice(2)));
    for (const annotation of outcome.report.annotations) {
      console.log(annotation);
    }
    if (outcome.success) {
      console.log(`[license-gate] PASSED — ${outcome.results.runtimeCount} runtime components comply with the policy.`);
      process.exit(0);
    }
    console.error(`[license-gate] FAILED — ${outcome.results.violations.length} blocking violation(s).`);
    process.exit(1);
  } catch (err) {
    console.log(formatAnnotation('error', `License Gate execution error: ${err.message}`));
    console.error(`[license-gate] ERROR: ${err.message}`);
    process.exit(1);
  }
}
