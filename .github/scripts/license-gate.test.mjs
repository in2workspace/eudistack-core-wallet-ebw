/**
 * Test suite for the vendored license gate.
 *
 * Runs with `node --test`, no framework and no third-party dependency, so it
 * executes in every repository that vendors the gate. Fixtures are built inline
 * and written to a temporary directory: the suite carries no fixture files.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  normalizeLicenseName,
  parseSpdxExpression,
  resolveDeclaredLicenses,
  evaluateComponentLicenses,
  selectGatedComponents,
  assertSbomVersionMatches,
  validateExceptionRecord,
  findApprovedException,
  loadPolicy,
  loadSbom,
  loadExceptions,
  runLicenseGate
} from './license-gate.mjs';

const ALLOWED = ['Apache-2.0', 'MIT', 'BSD-2-Clause', 'BSD-3-Clause', 'MPL-2.0', 'EPL-2.0', 'CC0-1.0', 'MIT-0', '0BSD', 'ISC', 'LicenseRef-PublicDomain'];

const REF_DATE = new Date('2026-08-27T00:00:00Z');

/** Builds a CycloneDX component. */
function component(name, licenses, extra = {}) {
  return { type: 'library', name, version: '1.0.0', purl: `pkg:maven/test/${name}@1.0.0?type=jar`, licenses, ...extra };
}

/** Builds a minimal CycloneDX 1.6 SBOM around the given components. */
function sbom(components, version = '1.0.0') {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    metadata: { component: { type: 'application', name: 'self', version, purl: 'pkg:maven/es.in2/self@1.0.0?type=jar' } },
    components
  };
}

/** Writes JSON into a fresh temp directory and returns the directory. */
function writeFixtures(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'license-gate-'));
  for (const [name, content] of Object.entries(files)) {
    const target = path.join(dir, name);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, typeof content === 'string' ? content : JSON.stringify(content, null, 2));
  }
  return dir;
}

// ---------------------------------------------------------------------------
// EC-03 — free-text license normalization
// ---------------------------------------------------------------------------

test('normalizeLicenseName resolves reviewed free-text names to SPDX', () => {
  assert.equal(normalizeLicenseName('Public Domain'), 'LicenseRef-PublicDomain');
  assert.equal(normalizeLicenseName('CC0 Universal'), 'CC0-1.0');
  assert.equal(normalizeLicenseName('Bouncy Castle Licence'), 'MIT');
  assert.equal(normalizeLicenseName('The Apache Software License, Version 2.0'), 'Apache-2.0');
});

test('normalizeLicenseName is insensitive to case and surrounding whitespace', () => {
  assert.equal(normalizeLicenseName('  APACHE   2.0 '), 'Apache-2.0');
});

test('normalizeLicenseName leaves an unknown name unresolved so it blocks', () => {
  assert.equal(normalizeLicenseName('BSD 3-clause License w/nuclear disclaimer'), null);
  assert.equal(normalizeLicenseName('Totally Made Up License'), null);
});

test('a normalized free-text name is allowed when its SPDX equivalent is', () => {
  const verdict = evaluateComponentLicenses(component('bcprov', [{ license: { name: 'Bouncy Castle Licence' } }]), ALLOWED);
  assert.equal(verdict.allowed, true);
});

test('an unknown free-text name blocks as UNNORMALIZED_LICENSE', () => {
  const verdict = evaluateComponentLicenses(component('jai', [{ license: { name: 'BSD 3-clause License w/nuclear disclaimer' } }]), ALLOWED);
  assert.equal(verdict.allowed, false);
  assert.equal(verdict.status, 'UNNORMALIZED_LICENSE');
});

test('a multi-licensed free-text name normalizes to a disjunction and passes on one allowed term', () => {
  const verdict = evaluateComponentLicenses(component('logback', [{ license: { name: 'EPL-2.0, GNU Lesser General Public License' } }]), ALLOWED);
  assert.equal(verdict.allowed, true);
  assert.match(verdict.declaredLicense, /EPL-2\.0 OR LGPL-2\.1/);
});

test('a multi-licensed free-text name blocks when no term is allowed', () => {
  const verdict = evaluateComponentLicenses(component('logback-old', [{ license: { name: 'EPL-1.0, GNU Lesser General Public License' } }]), ALLOWED);
  assert.equal(verdict.allowed, false);
});

// ---------------------------------------------------------------------------
// EC-01 — SPDX expressions
// ---------------------------------------------------------------------------

test('a pure OR expression passes when one term is allowed', () => {
  const verdict = evaluateComponentLicenses(component('dual', [{ expression: 'MIT OR GPL-3.0-only' }]), ALLOWED);
  assert.equal(verdict.allowed, true);
});

test('a pure OR expression blocks when no term is allowed', () => {
  const verdict = evaluateComponentLicenses(component('copyleft', [{ expression: 'GPL-3.0-only OR AGPL-3.0-only' }]), ALLOWED);
  assert.equal(verdict.allowed, false);
});

test('an AND expression blocks rather than being interpreted', () => {
  const verdict = evaluateComponentLicenses(component('conjunct', [{ expression: 'Apache-2.0 AND GPL-3.0-only' }]), ALLOWED);
  assert.equal(verdict.allowed, false);
  assert.equal(verdict.status, 'UNPARSEABLE_EXPRESSION');
});

test('WITH, + and nested parentheses block as unparseable', () => {
  assert.equal(parseSpdxExpression('GPL-2.0-only WITH Classpath-exception-2.0').type, 'UNPARSEABLE_EXPRESSION');
  assert.equal(parseSpdxExpression('LGPL-2.1+').type, 'UNPARSEABLE_EXPRESSION');
  assert.equal(parseSpdxExpression('(MIT OR Apache-2.0) AND BSD-3-Clause').type, 'UNPARSEABLE_EXPRESSION');
});

test('an operator keyword inside an identifier is not read as an operator', () => {
  // Regression: `\bWITH\b` also matches the hyphens of
  // `GPL-2.0-with-classpath-exception`, which blocked an ordinary disjunction
  // as unparseable and pushed jakarta.annotation-api into the exception file.
  const parsed = parseSpdxExpression('EPL-2.0 OR GPL-2.0-with-classpath-exception');
  assert.equal(parsed.type, 'EXPRESSION_OR');
  assert.deepEqual(parsed.terms, ['EPL-2.0', 'GPL-2.0-with-classpath-exception']);

  const verdict = evaluateComponentLicenses(
    component('jakarta.annotation-api', [{ license: { name: 'EPL-2.0, GPL-2.0-with-classpath-exception' } }]),
    ALLOWED);
  assert.equal(verdict.allowed, true);
});

test('a bare identifier inside an expression field is treated as an SPDX id', () => {
  const parsed = parseSpdxExpression('Apache-2.0');
  assert.equal(parsed.type, 'SPDX_ID');
  assert.equal(parsed.id, 'Apache-2.0');
});

// ---------------------------------------------------------------------------
// EC-02 — several independent license entries
// ---------------------------------------------------------------------------

test('several license entries must all be allowed', () => {
  const allowed = evaluateComponentLicenses(component('multi-ok', [{ license: { id: 'MIT' } }, { license: { id: 'Apache-2.0' } }]), ALLOWED);
  assert.equal(allowed.allowed, true);

  const blocked = evaluateComponentLicenses(component('multi-ko', [{ license: { id: 'MIT' } }, { license: { id: 'GPL-3.0-only' } }]), ALLOWED);
  assert.equal(blocked.allowed, false);
});

// ---------------------------------------------------------------------------
// FR-11 — no declared license
// ---------------------------------------------------------------------------

test('a component with no declared license blocks', () => {
  const verdict = evaluateComponentLicenses(component('anon', []), ALLOWED);
  assert.equal(verdict.allowed, false);
  assert.equal(verdict.status, 'NO_LICENSE');
});

test('a license object with neither id nor name blocks', () => {
  const verdict = evaluateComponentLicenses(component('hollow', [{ license: {} }]), ALLOWED);
  assert.equal(verdict.allowed, false);
});

test('resolveDeclaredLicenses reports NO_LICENSE when the array is absent', () => {
  assert.equal(resolveDeclaredLicenses({ name: 'x' }).status, 'NO_LICENSE');
});

// ---------------------------------------------------------------------------
// EC-04 / EC-09 — scope and self component
// ---------------------------------------------------------------------------

test('build and test components are separated from runtime components', () => {
  const doc = sbom([
    component('runtime-dep', [{ license: { id: 'MIT' } }]),
    component('npm-dev-dep', [{ license: { id: 'GPL-3.0-only' } }], { properties: [{ name: 'cdx:npm:package:development', value: 'true' }] }),
    component('gradle-excluded', [{ license: { id: 'GPL-3.0-only' } }], { scope: 'excluded' })
  ]);

  const { runtimeComponents, devTestComponents } = selectGatedComponents(doc);
  assert.deepEqual(runtimeComponents.map(c => c.name), ['runtime-dep']);
  assert.deepEqual(devTestComponents.map(c => c.name).sort(), ['gradle-excluded', 'npm-dev-dep']);
});

test('the repository own artifact is excluded from evaluation', () => {
  const doc = sbom([
    { type: 'application', name: 'self', version: '1.0.0', purl: 'pkg:maven/es.in2/self@1.0.0?type=jar', licenses: [] },
    component('dep', [{ license: { id: 'MIT' } }])
  ]);

  const { runtimeComponents, selfComponent } = selectGatedComponents(doc);
  assert.equal(selfComponent?.name, 'self');
  assert.deepEqual(runtimeComponents.map(c => c.name), ['dep']);
});

test('a blocked build-only component warns instead of blocking', () => {
  const dir = writeFixtures({
    'policy.json': { allow: ALLOWED },
    'sbom.json': sbom([
      component('runtime-dep', [{ license: { id: 'MIT' } }]),
      component('dev-dep', [{ license: { id: 'GPL-3.0-only' } }], { properties: [{ name: 'cdx:npm:package:development', value: 'true' }] })
    ])
  });

  const outcome = runLicenseGate({
    sbomPath: path.join(dir, 'sbom.json'),
    policyPath: path.join(dir, 'policy.json'),
    exceptionsPath: path.join(dir, 'missing.json'),
    gatedScopes: ['runtime'],
    refDate: REF_DATE
  });

  assert.equal(outcome.success, true);
  assert.equal(outcome.results.warnings.length, 1);
  assert.equal(outcome.results.warnings[0].type, 'DEV_TEST_UNALLOWED');
});

// ---------------------------------------------------------------------------
// ES-03 — SBOM version matches the release
// ---------------------------------------------------------------------------

test('the SBOM version must match the release version', () => {
  const doc = sbom([component('dep', [{ license: { id: 'MIT' } }])], '1.4.0');
  assert.equal(assertSbomVersionMatches(doc, '1.4.0'), true);
  assert.equal(assertSbomVersionMatches(doc, 'v1.4.0'), true);
  assert.throws(() => assertSbomVersionMatches(doc, '1.5.0'), /ES-03/);
});

test('no expected version means no version check', () => {
  assert.equal(assertSbomVersionMatches(sbom([component('dep', [])]), undefined), true);
});

// ---------------------------------------------------------------------------
// EC-05 / EC-06 / NFR-S-220-05 — exceptions
// ---------------------------------------------------------------------------

const VALID_EXCEPTION = {
  purl: 'pkg:maven/test/blocked@1.0.0?type=jar',
  license: 'GPL-3.0-only',
  reason: 'Pending replacement',
  approved_by: 'DevOps Lead',
  approved_on: '2026-08-01',
  expires_on: '2026-10-30',
  ticket: 'EUD-999'
};

test('an exception record requires every field', () => {
  assert.equal(validateExceptionRecord(VALID_EXCEPTION), true);
  for (const field of ['purl', 'license', 'reason', 'approved_by', 'approved_on', 'expires_on', 'ticket']) {
    const record = { ...VALID_EXCEPTION };
    delete record[field];
    assert.throws(() => validateExceptionRecord(record), new RegExp(field));
  }
});

test('an exception may not outlive the 180-day cap', () => {
  assert.throws(
    () => validateExceptionRecord({ ...VALID_EXCEPTION, approved_on: '2026-01-01', expires_on: '2026-12-31' }),
    /NFR-S-220-05/
  );
});

test('an exception must pin a version', () => {
  assert.throws(() => validateExceptionRecord({ ...VALID_EXCEPTION, purl: 'pkg:maven/test/blocked' }), /EC-06/);
});

test('an expired exception no longer applies', () => {
  const outcome = findApprovedException([VALID_EXCEPTION], VALID_EXCEPTION.purl, new Date('2026-11-01T00:00:00Z'));
  assert.equal(outcome.matched, false);
  assert.equal(outcome.reason, 'EXCEPTION_EXPIRED');
});

test('an exception close to expiry still applies and is flagged', () => {
  const outcome = findApprovedException([VALID_EXCEPTION], VALID_EXCEPTION.purl, new Date('2026-10-20T00:00:00Z'));
  assert.equal(outcome.matched, true);
  assert.equal(outcome.nearExpiry, true);
});

test('an exception approved for another version does not carry over', () => {
  const outcome = findApprovedException([VALID_EXCEPTION], 'pkg:maven/test/blocked@2.0.0?type=jar', REF_DATE);
  assert.equal(outcome.matched, false);
  assert.equal(outcome.reason, 'EXCEPTION_OTHER_VERSION');
});

test('a live exception turns a violation into an applied exception', () => {
  const blocked = component('blocked', [{ license: { id: 'GPL-3.0-only' } }]);
  const dir = writeFixtures({
    'policy.json': { allow: ALLOWED },
    'sbom.json': sbom([blocked]),
    'exceptions.json': { exceptions: [{ ...VALID_EXCEPTION, purl: blocked.purl }] }
  });

  const outcome = runLicenseGate({
    sbomPath: path.join(dir, 'sbom.json'),
    policyPath: path.join(dir, 'policy.json'),
    exceptionsPath: path.join(dir, 'exceptions.json'),
    gatedScopes: ['runtime'],
    refDate: REF_DATE
  });

  assert.equal(outcome.success, true);
  assert.equal(outcome.results.approvedExceptions.length, 1);
});

test('a missing exceptions file means no exceptions, not an error', () => {
  assert.deepEqual(loadExceptions('does/not/exist.json'), []);
});

// ---------------------------------------------------------------------------
// ES-01 / ES-02 / EC-08 — input errors, all fail closed
// ---------------------------------------------------------------------------

test('a missing or malformed policy is an error', () => {
  const dir = writeFixtures({ 'broken.json': '{ not json', 'empty.json': { allow: [] } });
  assert.throws(() => loadPolicy(path.join(dir, 'absent.json')), /ES-01/);
  assert.throws(() => loadPolicy(path.join(dir, 'broken.json')), /ES-01/);
  assert.throws(() => loadPolicy(path.join(dir, 'empty.json')), /ES-01/);
});

test('a missing or malformed SBOM is an error', () => {
  const dir = writeFixtures({ 'broken.json': '{ not json' });
  assert.throws(() => loadSbom(path.join(dir, 'absent.json')), /ES-02/);
  assert.throws(() => loadSbom(path.join(dir, 'broken.json')), /ES-02/);
});

test('an SBOM with no components is an error rather than a silent pass', () => {
  const dir = writeFixtures({ 'empty.json': { bomFormat: 'CycloneDX', specVersion: '1.6', components: [] } });
  assert.throws(() => loadSbom(path.join(dir, 'empty.json')), /EC-08/);
});

test('malformed exceptions are an error', () => {
  const dir = writeFixtures({ 'broken.json': '{ not json' });
  assert.throws(() => loadExceptions(path.join(dir, 'broken.json')), /ES-01/);
});

// ---------------------------------------------------------------------------
// End to end
// ---------------------------------------------------------------------------

test('a compliant SBOM passes and a blocked one fails with an annotation', () => {
  const compliant = writeFixtures({
    'policy.json': { allow: ALLOWED },
    'sbom.json': sbom([component('ok', [{ license: { id: 'Apache-2.0' } }])])
  });
  const passing = runLicenseGate({
    sbomPath: path.join(compliant, 'sbom.json'),
    policyPath: path.join(compliant, 'policy.json'),
    exceptionsPath: path.join(compliant, 'none.json'),
    gatedScopes: ['runtime'],
    refDate: REF_DATE
  });
  assert.equal(passing.success, true);
  assert.equal(passing.results.allowedCount, 1);

  const blocked = writeFixtures({
    'policy.json': { allow: ALLOWED },
    'sbom.json': sbom([component('bad', [{ license: { id: 'AGPL-3.0-only' } }])])
  });
  const failing = runLicenseGate({
    sbomPath: path.join(blocked, 'sbom.json'),
    policyPath: path.join(blocked, 'policy.json'),
    exceptionsPath: path.join(blocked, 'none.json'),
    gatedScopes: ['runtime'],
    refDate: REF_DATE
  });
  assert.equal(failing.success, false);
  assert.equal(failing.results.violations.length, 1);
  assert.match(failing.report.annotations[0], /^::error/);
  assert.match(failing.report.annotations[0], /AGPL-3\.0-only/);
});
