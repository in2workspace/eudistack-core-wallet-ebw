#!/usr/bin/env python3
"""
joiner.py
Merges vault_keys.csv, credentials.csv and user_entity.csv into unified_data.csv.

User join strategy (in order):
  1. credentials.user_id      == user_entity.id          → user_id_match_type = 'by_id'
  2. mandatee email (json_vc) == user_entity.email        → user_id_match_type = 'by_email'
  3. mandatee email (json_vc) == user_entity.username     → user_id_match_type = 'by_username'
  4. not found                                            → user_id_match_type = ''
"""

import base64
import csv
import json
import os
import sys
from datetime import datetime, timezone

VAULT_KEYS_FILE   = 'vault_keys.csv'
CREDENTIALS_FILE  = 'credentials.csv'
USERS_FILE        = 'user_entity.csv'
UNIFIED_DATA_FILE = 'unified_data.csv'

# ─── CONFIGURACIÓN POR ENTORNO ────────────────────────────────────────────────
# Cambiar este valor según el entorno antes de ejecutar el script.
# Es el realm_id del Keycloak ORIGEN que contiene los usuarios a migrar.
# Se usa para desambiguar cuando un mismo email aparece en varios realms:
# se prefiere el usuario de este realm frente a duplicados de otros realms.
#
# Cómo obtenerlo:
#   SELECT id, name FROM realm;   (en la BD Keycloak origen)
#
# SBX: 'bf013390-0d36-4d69-b775-b8b47a4df472'
# PRD: '<completar antes de ejecutar en producción>'
TARGET_REALM = 'bf013390-0d36-4d69-b775-b8b47a4df472'  # ← actualizar para PRD

UNIFIED_DATA_COLUMNS = [
    # ── credentials.csv fields ────────────────────────────────────────
    'credential_db_id',
    'credential_id',
    'old_user_id',
    'credential_type',
    'credential_status',
    'credential_format',
    'credential_data',
    'json_vc',
    'credential_created_at',
    'credential_updated_at',
    # ── extracted from json_vc (or credential_data JWT) ───────────────
    'did_key',
    'mandatee_email',
    'mandatee_first_name',
    'mandatee_last_name',
    'issuance_date',
    'expiration_date',
    'issuer',
    # ── vault_keys.csv (joined by did_key) ────────────────────────────
    'jwk_d',
    'jwk_x',
    'jwk_y',
    'jwk_kty',
    'jwk_crv',
    'jwk_alg',
    # ── user_entity.csv (joined by user_id, then by email) ────────────
    'user_id_match_type',   # 'by_id' | 'by_email' | 'by_username' | ''
    'user_email',
    'user_created_at',      # converted from created_timestamp (ms epoch)
    'user_first_name',
    'user_last_name',
    'user_username',
    'user_realm_id',
    # ── flags and derived ─────────────────────────────────────────────
    'vault_key_found',
    'user_found',
]

_EMPTY_USER_FIELDS = {
    'user_id_match_type': '',
    'user_email':         '',
    'user_created_at':    '',
    'user_first_name':    '',
    'user_last_name':     '',
    'user_username':      '',
    'user_realm_id':      '',
}


# ─── helpers ────────────────────────────────────────────────────────────────

def ts_ms_to_iso(ts_str: str) -> str:
    """
    Convert a Unix timestamp in MILLISECONDS to 'YYYY-MM-DD HH:MM:SS' (UTC).

    user_entity.csv stores created_timestamp as a 13-digit epoch in ms
    (e.g. 1746456505185 → 2025-05-05 18:28:25).
    Returns the raw string unchanged if it cannot be converted.
    """
    try:
        ms = int(ts_str)
        dt = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError, OSError):
        return (ts_str or '').strip()


def decode_jwt_payload(jwt_str: str) -> dict:
    """
    Decode the payload section of a JWT string without signature verification.

    JWTs are three base64url parts separated by '.'.  The middle part (index 1)
    is the payload.  We add the necessary '=' padding, swap url-safe chars back
    to standard base64, and parse the resulting JSON.
    Returns {} on any error.
    """
    try:
        parts = (jwt_str or '').strip().split('.')
        if len(parts) != 3:
            return {}
        payload_b64 = parts[1].replace('-', '+').replace('_', '/')
        padding = len(payload_b64) % 4
        if padding:
            payload_b64 += '=' * (4 - padding)
        payload_bytes = base64.b64decode(payload_b64)
        return json.loads(payload_bytes.decode('utf-8'))
    except Exception:
        return {}


def _str(value) -> str:
    """Strip and coerce a value to str, returning '' for None/falsy."""
    return (str(value) if value is not None else '').strip()


# ─── vault keys ─────────────────────────────────────────────────────────────

def load_vault_keys(filepath: str) -> dict:
    """
    Read vault_keys.csv.
    Returns  { did_key → {jwk_d, jwk_x, jwk_y, jwk_kty, jwk_crv, jwk_alg} }.

    The dict key is the full did:key string from the 'did_key' column.
    """
    keys: dict = {}
    with open(filepath, newline='', encoding='utf-8-sig') as f:
        for row in csv.DictReader(f):
            dk = row['did_key'].strip()
            if dk:
                keys[dk] = {
                    'jwk_d':   row['jwk_d'].strip(),
                    'jwk_x':   row['jwk_x'].strip(),
                    'jwk_y':   row['jwk_y'].strip(),
                    'jwk_kty': row['jwk_kty'].strip(),
                    'jwk_crv': row['jwk_crv'].strip(),
                    'jwk_alg': row['jwk_alg'].strip(),
                }
    return keys


# ─── users ───────────────────────────────────────────────────────────────────

def load_users(filepath: str):
    """
    Read user_entity.csv and build two lookup indexes.

    Returns (users_by_id, users_by_email):

    users_by_id    : { uuid   → raw row dict }
                     Direct match on user_entity.id

    users_by_email : { email  → raw row dict }
                     Deduplication rule when the same email appears in several
                     rows (Keycloak allows multiple realms):
                       1st  prefer TARGET_REALM (bf013390...)
                       2nd  prefer the oldest created_timestamp (original acct)

    Fallback email sources (checked in order when the 'email' column is empty):
      - 'username' field if it contains '@'
    """
    users_by_id: dict          = {}
    candidates: dict[str, list] = {}   # raw email → [rows]

    with open(filepath, newline='', encoding='utf-8-sig') as f:
        for row in csv.DictReader(f):
            row = dict(row)

            uid = row.get('id', '').strip()
            if uid:
                users_by_id[uid] = row

            # Determine usable email for this row
            email = row.get('email', '').strip().lower()
            if not email:
                username = row.get('username', '').strip().lower()
                if '@' in username:
                    email = username

            if email:
                candidates.setdefault(email, []).append(row)

    # Deduplicate: for each email keep the single best candidate
    users_by_email: dict = {}
    for email, rows in candidates.items():
        target = [r for r in rows if r.get('realm_id', '') == TARGET_REALM]
        pool   = target if target else rows

        def _ts(r) -> int:
            try:
                return int(r.get('created_timestamp') or '0')
            except ValueError:
                return 0

        users_by_email[email] = min(pool, key=_ts)

    return users_by_id, users_by_email


def user_row_to_fields(udata: dict, match_type: str) -> dict:
    """
    Map one user_entity row to the user_* columns expected in unified_data.csv.

    Notable mapping:
      created_timestamp (ms epoch int)  →  user_created_at (ISO datetime UTC)
    """
    return {
        'user_id_match_type': match_type,
        'user_email':         _str(udata.get('email')),
        'user_created_at':    ts_ms_to_iso(_str(udata.get('created_timestamp'))),
        'user_first_name':    _str(udata.get('first_name')),
        'user_last_name':     _str(udata.get('last_name')),
        'user_username':      _str(udata.get('username')),
        'user_realm_id':      _str(udata.get('realm_id')),
    }


# ─── VC field extraction ─────────────────────────────────────────────────────

def extract_vc_fields(json_vc_str: str, credential_data_str: str = '') -> dict:
    """
    Extract migration-relevant scalar fields from a credential.

    Tries two sources in order:
      1. json_vc  — already-decoded JSON (present in both v1 and v2 credentials)
      2. credential_data — raw JWT string; its payload is base64url-decoded and
                           parsed when json_vc is empty or unparseable

    Handles two credential schema versions:
      v1 (old):  first_name / last_name  (snake_case),  issuer as plain string,
                 issuanceDate / expirationDate
      v2 (new):  firstName  / lastName   (camelCase),   issuer as object {id:...},
                 validFrom  / validUntil

    credentialSubject paths attempted:
      A. vc.credentialSubject.mandate.mandatee  (LEARCredentialEmployee, both versions)
      B. vc.vc.credentialSubject.mandate.mandatee  (JWT payload with nested 'vc' key)
      C. vc.credentialSubject.id  (simpler/older format fallback)
      D. JWT payload 'sub' field  (always present in JWT, equals did:key)

    Returns a dict with these keys (all default to ''):
      did_key, mandatee_email, mandatee_first_name, mandatee_last_name,
      issuance_date, expiration_date, issuer
    """
    result = {
        'did_key': '', 'mandatee_email': '',
        'mandatee_first_name': '', 'mandatee_last_name': '',
        'issuance_date': '', 'expiration_date': '', 'issuer': '',
    }

    # ── resolve VC JSON from one of the two sources ───────────────────
    vc: dict = {}
    raw = (json_vc_str or '').strip()
    if raw:
        try:
            vc = json.loads(raw)
        except json.JSONDecodeError:
            pass

    jwt_payload: dict = {}
    if not vc and (credential_data_str or '').strip():
        jwt_payload = decode_jwt_payload(credential_data_str)
        # JWT payload may embed the VC under a 'vc' key
        vc = jwt_payload.get('vc') or jwt_payload

    if not vc:
        return result

    # ── locate credentialSubject ──────────────────────────────────────
    cs = vc.get('credentialSubject') or vc.get('vc', {}).get('credentialSubject')
    if isinstance(cs, list):
        cs = cs[0] if cs else None

    # ── extract mandatee fields ───────────────────────────────────────
    if cs and isinstance(cs, dict):
        try:
            mandatee = cs['mandate']['mandatee']
            result['did_key'] = _str(mandatee.get('id'))
            result['mandatee_email'] = _str(mandatee.get('email'))
            # v1 uses snake_case, v2 uses camelCase — try both
            result['mandatee_first_name'] = _str(
                mandatee.get('first_name') or mandatee.get('firstName'))
            result['mandatee_last_name'] = _str(
                mandatee.get('last_name') or mandatee.get('lastName'))
        except (KeyError, TypeError):
            pass

        # Fallback C: credentialSubject.id
        if not result['did_key']:
            did = _str(cs.get('id'))
            if did.startswith('did:key:'):
                result['did_key'] = did

    # Fallback D: JWT 'sub' claim
    if not result['did_key'] and jwt_payload:
        sub = _str(jwt_payload.get('sub'))
        if sub.startswith('did:key:'):
            result['did_key'] = sub

    # ── dates ─────────────────────────────────────────────────────────
    # v1 uses issuanceDate/expirationDate; v2 uses validFrom/validUntil
    result['issuance_date']   = _str(vc.get('issuanceDate')   or vc.get('validFrom'))
    result['expiration_date'] = _str(vc.get('expirationDate') or vc.get('validUntil'))

    # ── issuer (string in v1, object with 'id' in v2) ─────────────────
    issuer_raw = vc.get('issuer', '')
    if isinstance(issuer_raw, dict):
        result['issuer'] = _str(issuer_raw.get('id'))
    else:
        result['issuer'] = _str(issuer_raw)

    return result


# ─── main ────────────────────────────────────────────────────────────────────

def main() -> None:
    for path in (VAULT_KEYS_FILE, CREDENTIALS_FILE, USERS_FILE):
        if not os.path.exists(path):
            sys.exit(f'ERROR: {path} no encontrado.')

    vault_keys = load_vault_keys(VAULT_KEYS_FILE)
    print(f'[vault_keys] {len(vault_keys)} claves cargadas.')

    users_by_id, users_by_email = load_users(USERS_FILE)
    print(f'[users] {len(users_by_id)} registros por ID, '
          f'{len(users_by_email)} emails únicos indexados.')

    counters = {
        'total': 0, 'valid': 0,
        'vault_found': 0, 'vault_missing': 0,
        'user_by_id': 0, 'user_by_email': 0,
        'user_by_username': 0, 'user_missing': 0,
    }

    with open(CREDENTIALS_FILE, newline='', encoding='utf-8-sig') as fin, \
         open(UNIFIED_DATA_FILE, 'w', newline='', encoding='utf-8') as fout:

        reader = csv.DictReader(fin)
        writer = csv.DictWriter(fout, fieldnames=UNIFIED_DATA_COLUMNS,
                                extrasaction='ignore')
        writer.writeheader()

        for row in reader:
            counters['total'] += 1
            status = _str(row.get('credential_status'))
            if status == 'VALID':
                counters['valid'] += 1

            # ── extract VC fields (handles v1, v2, JWT) ──────────────
            vc_fields = extract_vc_fields(
                row.get('json_vc') or '',
                row.get('credential_data') or '',
            )
            did_key = vc_fields['did_key']

            # ── vault key lookup ──────────────────────────────────────
            vk = vault_keys.get(did_key, {})
            vault_found = bool(vk)
            counters['vault_found' if vault_found else 'vault_missing'] += 1

            # ── user lookup: by_id → by_email → by_username ───────────
            old_user_id  = _str(row.get('user_id'))
            udata        = users_by_id.get(old_user_id)
            match_type   = ''

            if udata:
                match_type = 'by_id'
                counters['user_by_id'] += 1
            else:
                m_email = vc_fields['mandatee_email'].lower()
                udata   = users_by_email.get(m_email) if m_email else None
                if udata:
                    # Distinguish: found via email field or via username field
                    actual_email = udata.get('email', '').strip().lower()
                    if actual_email == m_email:
                        match_type = 'by_email'
                        counters['user_by_email'] += 1
                    else:
                        match_type = 'by_username'
                        counters['user_by_username'] += 1

            if udata:
                user_fields = user_row_to_fields(udata, match_type)
                user_found  = True
            else:
                user_fields = dict(_EMPTY_USER_FIELDS)
                user_found  = False
                counters['user_missing'] += 1

            out_row = {
                # credentials.csv
                'credential_db_id':      _str(row.get('id')),
                'credential_id':         _str(row.get('credential_id')),
                'old_user_id':           old_user_id,
                'credential_type':       _str(row.get('credential_type')),
                'credential_status':     status,
                'credential_format':     _str(row.get('credential_format')),
                'credential_data':       row.get('credential_data', ''),
                'json_vc':               row.get('json_vc', ''),
                'credential_created_at': _str(row.get('created_at')),
                'credential_updated_at': _str(row.get('updated_at')),
                # vc fields
                'did_key':             vc_fields['did_key'],
                'mandatee_email':      vc_fields['mandatee_email'],
                'mandatee_first_name': vc_fields['mandatee_first_name'],
                'mandatee_last_name':  vc_fields['mandatee_last_name'],
                'issuance_date':       vc_fields['issuance_date'],
                'expiration_date':     vc_fields['expiration_date'],
                'issuer':              vc_fields['issuer'],
                # vault keys (empty when vault_found=False)
                'jwk_d':   vk.get('jwk_d',   ''),
                'jwk_x':   vk.get('jwk_x',   ''),
                'jwk_y':   vk.get('jwk_y',   ''),
                'jwk_kty': vk.get('jwk_kty', ''),
                'jwk_crv': vk.get('jwk_crv', ''),
                'jwk_alg': vk.get('jwk_alg', ''),
                # user fields
                **user_fields,
                # flags
                'vault_key_found': str(vault_found),
                'user_found':      str(user_found),
            }
            writer.writerow(out_row)

    print(f'[output] {UNIFIED_DATA_FILE} escrito.')
    _print_summary(counters)


def _print_summary(c: dict) -> None:
    user_found_total = c['user_by_id'] + c['user_by_email'] + c['user_by_username']
    print()
    print('=' * 60)
    print('RESUMEN')
    print('=' * 60)
    print(f'  Total filas procesadas        : {c["total"]:>6}')
    print(f'  credential_status=VALID       : {c["valid"]:>6}')
    print()
    print(f'  vault_key_found=True          : {c["vault_found"]:>6}')
    print(f'  vault_key_found=False         : {c["vault_missing"]:>6}')
    print()
    print(f'  Usuario encontrado (total)    : {user_found_total:>6}')
    print(f'    · por user_id (directo)     : {c["user_by_id"]:>6}')
    print(f'    · por email  (fallback)     : {c["user_by_email"]:>6}')
    print(f'    · por username (fallback)   : {c["user_by_username"]:>6}')
    print(f'  Usuario NO encontrado         : {c["user_missing"]:>6}')
    print('=' * 60)


if __name__ == '__main__':
    main()
