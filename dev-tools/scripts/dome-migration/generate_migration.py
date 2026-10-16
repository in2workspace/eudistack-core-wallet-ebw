#!/usr/bin/env python3
"""
generate_migration.py
Reads unified_data.csv (preferred) or vault_keys.csv + credentials.csv and writes:
  migration_private_keys.sql             — INSERTs for dome_business_wallet.holder_key
  migration_credentials.sql — INSERTs for dome_business_wallet.wallet_credential
  skipped.csv               — rows that could not be processed

Mode selection (automatic):
  - unified_data.csv present  → run_from_unified_data()
  - unified_data.csv absent   → run_from_csv()  (legacy, vault_keys + credentials)
"""

import base64
import csv
import json
import os
import sys
from datetime import datetime

VAULT_KEYS_FILE   = 'vault_keys.csv'
CREDENTIALS_FILE  = 'credentials.csv'
UNIFIED_DATA_CSV  = 'unified_data.csv'
OUTPUT_SQL        = 'migration_private_keys.sql'
OUTPUT_CREDS_SQL  = 'migration_credentials.sql'
OUTPUT_ROLLBACK   = 'rollback.sql'
SKIPPED_CSV       = 'skipped.csv'
BATCH_SIZE        = 50

# Credential types that are too generic to be the primary type identifier
_GENERIC_VC_TYPES = {'VerifiableCredential', 'VerifiablePresentation',
                     'VerifiableAttestation'}

# issuer_metadata per credential type — sourced from:
# GET https://issuer.dome-marketplace-sbx.org/.well-known/openid-credential-issuer
# Field: credential_configurations_supported.<type>
_ISSUER_METADATA: dict[str, str] = {
    'LEARCredentialEmployee': json.dumps({
        'format': 'jwt_vc_json',
        'scope': 'lear_credential_employee',
        'cryptographic_binding_methods_supported': ['did:key'],
        'credential_signing_alg_values_supported': ['ES256'],
        'credential_definition': {
            'type': ['VerifiableCredential', 'LEARCredentialEmployee'],
        },
        'proof_types_supported': {
            'jwt': {'proof_signing_alg_values_supported': ['ES256']},
        },
    }, separators=(',', ':')),
    'LEARCredentialMachine': json.dumps({
        'format': 'jwt_vc_json',
        'scope': 'lear_credential_machine',
        'cryptographic_binding_methods_supported': ['did:key'],
        'credential_signing_alg_values_supported': ['ES256'],
        'credential_definition': {
            'type': ['VerifiableCredential', 'LEARCredentialMachine'],
        },
        'proof_types_supported': {
            'jwt': {'proof_signing_alg_values_supported': ['ES256']},
        },
    }, separators=(',', ':')),
}

# ─── helpers ─────────────────────────────────────────────────────────────────

def base64url_to_b64std(b64url: str) -> str:
    """Convert Base64url (no padding) to standard Base64 with padding."""
    b64 = b64url.replace('-', '+').replace('_', '/')
    rem = len(b64) % 4
    if rem:
        b64 += '=' * (4 - rem)
    return b64


def escape_sql(value: str) -> str:
    """Escape single quotes for PostgreSQL string literals."""
    return value.replace("'", "''")


def _clean_uuid(value: str) -> str:
    """Strip 'urn:uuid:' prefix if present, returning the bare UUID."""
    return value.removeprefix('urn:uuid:')


def _sql_str(value: str) -> str:
    """Return SQL string literal or NULL."""
    return f"'{escape_sql(value)}'" if value else 'NULL'


def _sql_ts(value: str) -> str:
    """Return timestamptz cast or NULL."""
    return f"'{escape_sql(value)}'::timestamptz" if value else 'NULL'


def _sql_user_lookup(email: str) -> str:
    """
    Return a SQL subquery that resolves an email to the wallet_user UUID.
    Returns NULL when email is empty.
    """
    if email:
        return (
            f"(SELECT id FROM wallet_user"
            f" WHERE email = '{escape_sql(email)}' LIMIT 1)"
        )
    return 'NULL'


# ─── EC private key encoding ─────────────────────────────────────────────────

def ec_jwk_d_to_raw_hex(d_b64url: str) -> str:
    """
    Decode a JWK EC 'd' value (Base64url) to the raw 32-byte EC private scalar
    and return it as a lowercase hex string.

    EBW HolderKeyFactory stores private_key as raw BYTEA and reconstructs it
    with new BigInteger(1, rawBytes) — it expects the bare 32-byte scalar, not
    a PKCS#8 / DER wrapper.

    Used in SQL as:  decode('<hex>', 'hex')
    """
    d_bytes = base64.b64decode(base64url_to_b64std(d_b64url))
    if len(d_bytes) < 32:
        d_bytes = d_bytes.rjust(32, b'\x00')
    elif len(d_bytes) > 32:
        raise ValueError(f'EC P-256 d is {len(d_bytes)} bytes, expected ≤ 32')
    return d_bytes.hex()


# ─── JWT helpers ──────────────────────────────────────────────────────────────

def decode_jwt_payload(jwt_str: str) -> dict:
    """
    Decode and return the payload of a compact JWT (three base64url parts
    separated by '.') without signature verification.
    Returns {} on any error.
    (Intentionally self-contained — this script has no imports from joiner.py)
    """
    try:
        parts = (jwt_str or '').strip().split('.')
        if len(parts) != 3:
            return {}
        b64 = parts[1].replace('-', '+').replace('_', '/')
        rem = len(b64) % 4
        if rem:
            b64 += '=' * (4 - rem)
        return json.loads(base64.b64decode(b64).decode('utf-8'))
    except Exception:
        return {}


def _is_machine_credential(row: dict) -> bool:
    """Return True if LEARCredentialMachine is among the credential types."""
    raw = (row.get('credential_type') or '').strip()
    types = [t.strip() for t in raw.strip('{}').split(',') if t.strip()]
    return 'LEARCredentialMachine' in types


def extract_credential_type(types) -> str:
    """
    Return the first non-generic type from a VC type list.
    Accepts a Python list or a PostgreSQL array literal: {T1,T2,...}.
    Falls back to 'LEARCredentialEmployee' if nothing specific is found.
    """
    if isinstance(types, str):
        types = [t.strip() for t in types.strip('{}').split(',') if t.strip()]
    for t in (types or []):
        if t.strip() not in _GENERIC_VC_TYPES:
            return t.strip()
    return (types[0].strip() if types else '') or 'LEARCredentialEmployee'


def extract_credential_jwt_fields(credential_data: str, json_vc_str: str) -> dict:
    """
    Extract credential table fields from two sources (JWT payload preferred,
    json_vc as fallback for old credentials that have no raw JWT).

    JWT payload fields used:
      iss → issuer         sub → subject & kid fallback
      vc.validFrom / vc.issuanceDate → issuance_date
      vc.validUntil / vc.expirationDate → expiration_date
      vc.type → credential_type

    Note: these JWTs do NOT contain a 'cnf' claim.  'sub' (the holder's
    did:key) is used as the kid fallback.

    Returns a dict with keys:
      kid, issuer, subject, issuance_date, expiration_date, credential_type
    All values default to ''.
    """
    result = {
        'kid': '', 'issuer': '', 'subject': '',
        'issuance_date': '', 'expiration_date': '', 'credential_type': '',
    }

    # ── Source 1: JWT payload ──────────────────────────────────────────
    payload = decode_jwt_payload(credential_data or '')
    if payload:
        cnf = payload.get('cnf') or {}
        kid = (cnf.get('kid') or '').strip()
        if not kid:
            kid = ((cnf.get('jwk') or {}).get('kid') or '').strip()
        if not kid:
            sub = (payload.get('sub') or '').strip()
            kid = sub if sub.startswith('did:key:') else ''
        result['kid']     = kid
        result['issuer']  = (payload.get('iss') or '').strip()
        result['subject'] = (payload.get('sub') or '').strip()

        vc_obj = payload.get('vc') or {}
        result['issuance_date']   = (
            vc_obj.get('validFrom')   or vc_obj.get('issuanceDate')   or '').strip()
        result['expiration_date'] = (
            vc_obj.get('validUntil')  or vc_obj.get('expirationDate') or '').strip()
        result['credential_type'] = extract_credential_type(vc_obj.get('type', []))
        return result

    # ── Source 2: json_vc fallback ────────────────────────────────────
    raw = (json_vc_str or '').strip()
    if not raw:
        return result
    try:
        vc = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return result

    issuer_raw = vc.get('issuer', '')
    result['issuer'] = (
        issuer_raw.get('id', '') if isinstance(issuer_raw, dict)
        else str(issuer_raw or '')
    ).strip()

    try:
        cs = vc.get('credentialSubject') or {}
        if isinstance(cs, list): cs = cs[0] if cs else {}
        did = cs['mandate']['mandatee']['id'].strip()
        result['subject'] = did
        result['kid']     = did
    except (KeyError, TypeError):
        pass

    result['issuance_date']   = str(
        vc.get('issuanceDate')   or vc.get('validFrom')  or '').strip()
    result['expiration_date'] = str(
        vc.get('expirationDate') or vc.get('validUntil') or '').strip()
    result['credential_type'] = extract_credential_type(vc.get('type', []))
    return result


# ─── NOT NULL pre-flight check ───────────────────────────────────────────────

def _missing_not_null_fields(row: dict) -> list[str]:
    """
    Return a list of wallet_credential NOT NULL columns that would be NULL for
    this row.  An empty list means the INSERT is safe to generate.
    """
    cred_data = (row.get('credential_data') or '').strip()
    if not cred_data:
        return ['credential_raw']

    jwt_f = extract_credential_jwt_fields(cred_data, row.get('json_vc') or '')
    kid           = jwt_f['kid']           or (row.get('did_key') or '').strip()
    issuer        = jwt_f['issuer']
    issuance_date = jwt_f['issuance_date']

    missing = []
    for name, val in [('kid', kid), ('issuer', issuer), ('issuance_date', issuance_date)]:
        if not val:
            missing.append(name)
    return missing


# ─── vault keys ──────────────────────────────────────────────────────────────

def load_vault_keys(filepath: str) -> dict:
    """Return { did_key → {d, x, y, kty, crv, alg} } from vault_keys.csv."""
    keys: dict = {}
    with open(filepath, newline='', encoding='utf-8-sig') as f:
        for row in csv.DictReader(f):
            dk = row['did_key'].strip()
            if dk:
                keys[dk] = {
                    'd':   row['jwk_d'].strip(),
                    'x':   row['jwk_x'].strip(),
                    'y':   row['jwk_y'].strip(),
                    'kty': row['jwk_kty'].strip(),
                    'crv': row['jwk_crv'].strip(),
                    'alg': row['jwk_alg'].strip(),
                }
    return keys


def load_unified_data(filepath: str) -> list[dict]:
    """Load a CSV file and return all rows as a list of dicts."""
    rows: list[dict] = []
    with open(filepath, newline='', encoding='utf-8-sig') as f:
        for row in csv.DictReader(f):
            rows.append(dict(row))
    return rows


# ─── VC field extraction (legacy mode) ───────────────────────────────────────

def extract_vc_fields(json_vc_str: str) -> dict:
    """
    Parse json_vc and return migration-relevant fields.
    Path: credentialSubject.mandate.mandatee.id → did:key
    """
    result = {
        'did_key': '', 'mandatee_email': '',
        'mandatee_first_name': '', 'mandatee_last_name': '',
        'issuance_date': '', 'expiration_date': '', 'issuer': '',
    }
    raw = (json_vc_str or '').strip()
    if not raw:
        return result
    try:
        vc = json.loads(raw)
    except json.JSONDecodeError:
        return result

    try:
        cs = vc.get('credentialSubject') or vc.get('vc', {}).get('credentialSubject', {})
        if isinstance(cs, list): cs = cs[0] if cs else {}
        mandatee = cs['mandate']['mandatee']
        result['did_key']             = (mandatee.get('id')        or '').strip()
        result['mandatee_email']      = (mandatee.get('email')      or '').strip()
        result['mandatee_first_name'] = (mandatee.get('first_name') or '').strip()
        result['mandatee_last_name']  = (mandatee.get('last_name')  or '').strip()
    except (KeyError, TypeError, AttributeError):
        pass

    result['issuance_date']   = str(vc.get('issuanceDate',   '') or '').strip()
    result['expiration_date'] = str(vc.get('expirationDate', '') or '').strip()
    result['issuer']          = str(vc.get('issuer',         '') or '').strip()
    return result


def extract_did_key(json_vc_str: str):
    """
    Return (did_key, None) or (None, error_message).
    Primary path: credentialSubject.mandate.mandatee.id
    """
    raw = (json_vc_str or '').strip()
    if not raw:
        return None, 'El campo json_vc está vacío'
    try:
        vc = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f'json_vc no es JSON válido: {exc}'
    try:
        cs = vc.get('credentialSubject') or vc.get('vc', {}).get('credentialSubject', {})
        if isinstance(cs, list): cs = cs[0] if cs else {}
        did = cs['mandate']['mandatee']['id'].strip()
        if did.startswith('did:key:'):
            return did, None
        return None, f'mandatee.id no es un did:key: {did!r}'
    except (KeyError, TypeError, AttributeError):
        pass
    return None, 'credentialSubject.mandate.mandatee.id no encontrado en json_vc'


# ─── SQL generation ──────────────────────────────────────────────────────────

def build_insert(credential_id: str, key: dict, user_email: str = '') -> str:
    """
    Build INSERT for dome_business_wallet.holder_key.
    private_key is the raw 32-byte EC scalar (HolderKeyFactory.reconstructEcPrivateKey
    expects new BigInteger(1, rawBytes) — no PKCS#8 wrapper).
    public_jwk never contains the private 'd' field.
    holder_id is resolved at INSERT time via a subquery on wallet_user.email.
    """
    credential_id = _clean_uuid(credential_id)
    raw_hex       = ec_jwk_d_to_raw_hex(key['d'])
    holder_id_sql = _sql_user_lookup(user_email)
    public_jwk = json.dumps(
        {'kty': key['kty'], 'crv': key['crv'],
         'x': key['x'], 'y': key['y'], 'alg': key['alg']},
        ensure_ascii=False, separators=(',', ':'),
    )
    return (
        "INSERT INTO dome_business_wallet.holder_key\n"
        "  (key_id, holder_id, credential_id, tenant_id,"
        " private_key, public_jwk, algorithm, format)\n"
        "VALUES (\n"
        "  gen_random_uuid(),\n"
        f"  {holder_id_sql},\n"
        f"  '{escape_sql(credential_id)}',\n"
        "  'dome',\n"
        f"  decode('{raw_hex}', 'hex'),\n"
        f"  '{escape_sql(public_jwk)}',\n"
        f"  '{escape_sql(key['alg'])}',\n"
        "  'jwt_vc_json'\n"
        ") ON CONFLICT DO NOTHING;"
    )


def build_wallet_credential_insert(row: dict, holder_key_sql: str = '') -> str:
    """
    Build INSERT for dome_business_wallet.wallet_credential.

    Field sources:
      id              ← credential_id
      user_id         ← subquery SELECT id FROM wallet_user WHERE email = '...'
      holder_key_id   ← subquery on holder_key.credential_id (resolved at run time)
      credential_raw  ← credential_data JWT string, or NULL for old credentials
      format          ← 'jwt_vc_json'
      credential_config_id ← cred_type (LEARCredentialEmployee or LEARCredentialMachine)
      kid             ← JWT payload cnf.kid → sub → did_key column
      credential_type ← first non-generic type from vc.type
      vct             ← NULL
      issuer          ← JWT payload iss → json_vc issuer
      subject         ← JWT payload sub → mandatee.id
      issuance_date   ← JWT vc.validFrom / issuanceDate
      expiration_date ← JWT vc.validUntil / expirationDate
      status          ← 'VALID'
      issuer_metadata ← NULL
      created_at      ← real credential creation date
      updated_at      ← NOW()
    """
    cred_id    = _clean_uuid((row.get('credential_id') or '').strip())
    user_email = (row.get('user_email')            or row.get('mandatee_email') or '').strip().lower()
    cred_data  = (row.get('credential_data')        or '').strip()
    created_at = (row.get('credential_created_at')  or '').strip()

    user_id_sql = _sql_user_lookup(user_email)

    jwt_f = extract_credential_jwt_fields(cred_data, row.get('json_vc') or '')

    kid             = jwt_f['kid']             or (row.get('did_key')         or '').strip()
    issuer          = jwt_f['issuer']          or (row.get('issuer')          or '').strip()
    subject         = jwt_f['subject']         or (row.get('did_key')         or '').strip()
    issuance_date   = jwt_f['issuance_date']   or (row.get('issuance_date')   or '').strip()
    expiration_date = jwt_f['expiration_date'] or (row.get('expiration_date') or '').strip()
    cred_type       = (jwt_f['credential_type']
                       or extract_credential_type(row.get('credential_type') or '')
                       or 'LEARCredentialEmployee')

    credential_raw_sql = f"'{escape_sql(cred_data)}'" if cred_data else 'NULL'
    created_at_sql     = f"'{escape_sql(created_at)}'" if created_at else 'NOW()'

    if holder_key_sql == 'NULL':
        hk_id_sql = 'NULL'
    else:
        hk_id_sql = (
            f"(SELECT key_id FROM dome_business_wallet.holder_key"
            f" WHERE credential_id = '{escape_sql(cred_id)}' LIMIT 1)"
        )

    raw_metadata = _ISSUER_METADATA.get(cred_type)
    issuer_metadata_sql = (
        f"'{escape_sql(raw_metadata)}'::jsonb" if raw_metadata else 'NULL'
    )

    return (
        "INSERT INTO dome_business_wallet.wallet_credential\n"
        "  (id, user_id, holder_key_id, credential_raw, format, credential_config_id,\n"
        "   kid, credential_type, vct, issuer, subject,\n"
        "   issuance_date, expiration_date, status, issuer_metadata,\n"
        "   created_at, updated_at)\n"
        "VALUES (\n"
        f"  '{escape_sql(cred_id)}',\n"
        f"  {user_id_sql},\n"
        f"  {hk_id_sql},\n"
        f"  {credential_raw_sql},\n"
        "  'jwt_vc_json',\n"
        f"  '{escape_sql(cred_type)}',\n"
        f"  {_sql_str(kid)},\n"
        f"  '{escape_sql(cred_type)}',\n"
        "  NULL,\n"
        f"  {_sql_str(issuer)},\n"
        f"  {_sql_str(subject)},\n"
        f"  {_sql_ts(issuance_date)},\n"
        f"  {_sql_ts(expiration_date)},\n"
        "  'VALID',\n"
        f"  {issuer_metadata_sql},\n"
        f"  {created_at_sql},\n"
        "  NOW()\n"
        ") ON CONFLICT DO NOTHING;"
    )


# ─── output writers ──────────────────────────────────────────────────────────

def write_sql(inserts: list[str], filepath: str, title: str) -> None:
    total         = len(inserts)
    total_batches = max(1, (total + BATCH_SIZE - 1) // BATCH_SIZE)

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write('-- ==============================================================\n')
        f.write(f'-- {title}\n')
        f.write(f'-- Generated : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n')
        f.write(f'-- Total INSERTs: {total}\n')
        f.write('-- ==============================================================\n')

        for idx, stmt in enumerate(inserts):
            if idx % BATCH_SIZE == 0:
                batch_num = idx // BATCH_SIZE + 1
                f.write(f'\n-- Tanda {batch_num}/{total_batches}\n\n')
            f.write(stmt + '\n')


def write_rollback_sql(cred_ids: list[str], hk_cred_ids: list[str]) -> None:
    """
    Write rollback.sql with exact DELETE statements for rows inserted by this
    migration run.  Uses the actual UUIDs so no manual extraction is needed.
    """
    def _id_list(ids: list[str]) -> str:
        return ',\n    '.join(f"'{escape_sql(i)}'" for i in ids)

    with open(OUTPUT_ROLLBACK, 'w', encoding='utf-8') as f:
        f.write('-- ==============================================================\n')
        f.write('-- rollback.sql\n')
        f.write(f'-- Generated : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n')
        f.write('-- Reverts ONLY the rows inserted by this migration run.\n')
        f.write('-- Execute holder_key DELETE after wallet_credential DELETE.\n')
        f.write('-- ==============================================================\n\n')

        f.write('-- Step 1: remove migrated credentials\n')
        f.write('DELETE FROM dome_business_wallet.wallet_credential\nWHERE id IN (\n    ')
        f.write(_id_list(cred_ids))
        f.write('\n);\n\n')

        f.write('-- Step 2: remove migrated holder keys\n')
        f.write('DELETE FROM dome_business_wallet.holder_key\nWHERE credential_id IN (\n    ')
        f.write(_id_list(hk_cred_ids))
        f.write('\n);\n')


def write_skipped(rows: list[dict], base_fieldnames: list[str]) -> None:
    fieldnames = base_fieldnames + ['skip_reason']
    with open(SKIPPED_CSV, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)


# ─── summary ─────────────────────────────────────────────────────────────────

def _print_summary(total_rows: int, valid_rows: int, n_hk: int,
                   n_cred: int, n_machine: int, n_skipped: int,
                   skip_reasons: dict) -> None:
    n_person = n_cred - n_machine
    print()
    print('=' * 62)
    print('RESUMEN DE MIGRACIÓN')
    print('=' * 62)
    print(f'  Total filas leídas                        : {total_rows:>6}')
    print(f'  Credenciales con status VALID             : {valid_rows:>6}')
    print(f'  INSERTs holder_key  (migration_private_keys.sql)       : {n_hk:>6}')
    print(f'  INSERTs wallet_credential (total)         : {n_cred:>6}')
    print(f'    · persona  (holder_key via subquery)    : {n_person:>6}')
    print(f'    · máquina  (holder_key_id = NULL)       : {n_machine:>6}')
    print(f'  Total skipped                             : {n_skipped:>6}')
    if skip_reasons:
        print()
        print('  Desglose de motivos de skip:')
        for reason, count in sorted(skip_reasons.items(), key=lambda kv: -kv[1]):
            print(f'    {count:5d}  {reason}')
    print('=' * 62)


# ─── unified_data.csv mode ─────────────────────────────────────────────────────────

def run_from_unified_data() -> None:
    print(f'[mode] Usando {UNIFIED_DATA_CSV}.')
    unified_rows = load_unified_data(UNIFIED_DATA_CSV)

    hk_inserts:   list[str]      = []
    cred_inserts: list[str]      = []
    skipped_rows: list[dict]     = []
    skip_reasons: dict[str, int] = {}
    rollback_cred_ids: list[str] = []
    rollback_hk_ids:   list[str] = []
    total_rows = len(unified_rows)
    valid_rows = 0
    n_machine  = 0

    for row in unified_rows:
        status = (row.get('credential_status') or '').strip()

        if status != 'VALID':
            reason = f'credential_status={status!r}'
            skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
            skipped_rows.append({**row, 'skip_reason': f'Estado no es VALID ({status!r})'})
            continue

        has_vault_key = (
            (row.get('vault_key_found') or '').strip() == 'True'
            and bool((row.get('jwk_d') or '').strip())
        )

        if not has_vault_key:
            if _is_machine_credential(row):
                # Machine credentials never have a vault key — only credential row, holder_key_id = NULL
                missing = _missing_not_null_fields(row)
                if missing:
                    reason = f'Campos NOT NULL vacíos: {", ".join(missing)}'
                    skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
                    skipped_rows.append({**row, 'skip_reason': reason})
                    continue
                valid_rows += 1
                n_machine  += 1
                cred_id_clean = _clean_uuid((row.get('credential_id') or '').strip())
                cred_inserts.append(build_wallet_credential_insert(row, holder_key_sql='NULL'))
                rollback_cred_ids.append(cred_id_clean)
                continue

            # Non-machine VALID without vault key → skip with explanation
            if (row.get('vault_key_found') or '').strip() != 'True':
                reason = 'vault_key_found=False'
            else:
                reason = 'jwk_d vacío (entrada en vault sin clave privada)'
            skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
            skipped_rows.append({**row, 'skip_reason': reason})
            continue

        missing = _missing_not_null_fields(row)
        if missing:
            reason = f'Campos NOT NULL vacíos: {", ".join(missing)}'
            skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
            skipped_rows.append({**row, 'skip_reason': reason})
            continue

        valid_rows += 1
        credential_id = (row.get('credential_id') or '').strip()
        user_email    = (row.get('user_email') or row.get('mandatee_email') or '').strip().lower()

        key = {
            'd':   (row.get('jwk_d',   '') or '').strip(),
            'x':   (row.get('jwk_x',   '') or '').strip(),
            'y':   (row.get('jwk_y',   '') or '').strip(),
            'kty': (row.get('jwk_kty', '') or '').strip(),
            'crv': (row.get('jwk_crv', '') or '').strip(),
            'alg': (row.get('jwk_alg', '') or '').strip(),
        }
        hk_inserts.append(build_insert(credential_id, key, user_email))
        cred_inserts.append(build_wallet_credential_insert(row))
        clean_id = _clean_uuid(credential_id)
        rollback_cred_ids.append(clean_id)
        rollback_hk_ids.append(clean_id)

    write_sql(hk_inserts, OUTPUT_SQL,
              'Migration: vault keys → dome_business_wallet.holder_key')
    print(f'[output] {OUTPUT_SQL} escrito con {len(hk_inserts)} INSERT(s).')

    write_sql(cred_inserts, OUTPUT_CREDS_SQL,
              'Migration: credentials → dome_business_wallet.wallet_credential')
    print(f'[output] {OUTPUT_CREDS_SQL} escrito con {len(cred_inserts)} INSERT(s).')

    write_rollback_sql(rollback_cred_ids, rollback_hk_ids)
    print(f'[output] {OUTPUT_ROLLBACK} escrito con {len(rollback_cred_ids)} credencial(es).')

    if skipped_rows:
        fieldnames = list(unified_rows[0].keys()) if unified_rows else []
        write_skipped(skipped_rows, fieldnames)
        print(f'[output] {SKIPPED_CSV} escrito con {len(skipped_rows)} fila(s).')

    _print_summary(total_rows, valid_rows, len(hk_inserts),
                   len(cred_inserts), n_machine, len(skipped_rows), skip_reasons)


# ─── legacy mode (vault_keys.csv + credentials.csv) ─────────────────────────
# Solo se activa si unified_data.csv no existe (es decir, si joiner.py no se
# ha ejecutado antes). En el flujo normal nunca llega aquí.

def run_from_csv() -> None:
    print(f'[mode] {UNIFIED_DATA_CSV} no encontrado — '
          f'usando {VAULT_KEYS_FILE} + {CREDENTIALS_FILE}.')

    if not os.path.exists(VAULT_KEYS_FILE):
        sys.exit(f'ERROR: {VAULT_KEYS_FILE} no encontrado.')
    vault_keys = load_vault_keys(VAULT_KEYS_FILE)
    print(f'[vault_keys] {len(vault_keys)} claves cargadas.')

    if not os.path.exists(CREDENTIALS_FILE):
        sys.exit(f'ERROR: {CREDENTIALS_FILE} no encontrado.')

    hk_inserts:   list[str]      = []
    cred_inserts: list[str]      = []
    skipped_rows: list[dict]     = []
    skip_reasons: dict[str, int] = {}
    total_rows = 0
    valid_rows = 0
    base_fieldnames: list[str]   = []

    with open(CREDENTIALS_FILE, newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        base_fieldnames = list(reader.fieldnames or [])

        for row in reader:
            total_rows += 1
            status = (row.get('credential_status') or '').strip()

            if status != 'VALID':
                reason = f'credential_status={status!r}'
                skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
                skipped_rows.append({**row,
                    'skip_reason': f'Estado no es VALID ({status!r})'})
                continue

            valid_rows += 1

            did_key, error = extract_did_key(row.get('json_vc') or '')
            if error:
                reason = 'did:key no extraíble de json_vc'
                skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
                skipped_rows.append({**row, 'skip_reason': error})
                continue

            if did_key not in vault_keys:
                reason = 'did:key no encontrado en vault_keys.csv'
                skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
                skipped_rows.append({**row,
                    'skip_reason': f'did:key {did_key!r} no está en vault_keys.csv'})
                continue

            credential_id = (row.get('credential_id') or '').strip()
            key = vault_keys[did_key]
            hk_inserts.append(build_insert(credential_id, key, ''))

            pseudo_row = {
                'credential_id':        credential_id,
                'credential_data':      row.get('credential_data', ''),
                'json_vc':              row.get('json_vc', ''),
                'credential_created_at': row.get('created_at', ''),
                'did_key':              did_key,
                'issuer':               '',
                'issuance_date':        '',
                'expiration_date':      '',
                'credential_type':      row.get('credential_type', ''),
            }
            cred_inserts.append(build_wallet_credential_insert(pseudo_row))

    write_sql(hk_inserts, OUTPUT_SQL,
              'Migration: vault keys → dome_business_wallet.holder_key')
    print(f'[output] {OUTPUT_SQL} escrito con {len(hk_inserts)} INSERT(s).')

    write_sql(cred_inserts, OUTPUT_CREDS_SQL,
              'Migration: credentials → dome_business_wallet.wallet_credential')
    print(f'[output] {OUTPUT_CREDS_SQL} escrito con {len(cred_inserts)} INSERT(s).')

    if skipped_rows:
        write_skipped(skipped_rows, base_fieldnames)
        print(f'[output] {SKIPPED_CSV} escrito con {len(skipped_rows)} fila(s).')

    _print_summary(total_rows, valid_rows, len(hk_inserts),
                   len(cred_inserts), 0, len(skipped_rows), skip_reasons)


# ─── entry point ─────────────────────────────────────────────────────────────

def main() -> None:
    if os.path.exists(UNIFIED_DATA_CSV):
        run_from_unified_data()
    else:
        run_from_csv()


if __name__ == '__main__':
    main()
