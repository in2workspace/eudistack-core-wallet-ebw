# Runbook: Migración de credenciales DOME Wallet → EUDIStack EBW

**Sistema origen:** DOME Wallet v1 (Keycloak + PostgreSQL)  
**Sistema destino:** EUDIStack EBW — schema `dome_business_wallet`  
**Tablas destino:** `holder_key`, `wallet_credential`  
**Tipos de credencial:** `LEARCredentialEmployee`, `LEARCredentialMachine`

---

## 1. Contexto

El sistema DOME Wallet antiguo almacenaba las credenciales verificables en PostgreSQL y las claves de holder en un servicio de vault separado. El nuevo EBW (Eudistack Business Wallet) consolida ambos en su propio schema:

- `holder_key` — clave EC P-256 del holder (raw 32 bytes), una por credencial de persona
- `wallet_credential` — credencial verificable en formato JWT, con metadatos indexables

Las credenciales `LEARCredentialMachine` no tienen clave de holder (la gestiona la aplicación): se migran solo a `wallet_credential` con `holder_key_id = NULL`.

---

## 2. Archivos del proceso

| Archivo | Descripción |
|---|---|
| `vault_keys.csv` | Export del vault: `did_key`, componentes JWK (`d`, `x`, `y`, `kty`, `crv`, `alg`) |
| `credentials.csv` | Export de la BD origen: credenciales con JWT, metadatos y usuario |
| `user_entity.csv` | Export de la BD origen: información de los usuarios |
| `joiner.py` | Une vault_keys + credentials + user_entity en `unified_data.csv` |
| `unified_data.csv` | Fichero intermedio consolidado (input de generate_migration) |
| `generate_migration.py` | Genera los dos ficheros SQL de migración |
| `migration_private_keys.sql` | INSERTs para `dome_business_wallet.holder_key` |
| `migration_credentials.sql` | INSERTs para `dome_business_wallet.wallet_credential` |
| `rollback.sql` | DELETEs exactos para revertir solo las filas migradas |
| `skipped.csv` | Filas descartadas con motivo |

---

## 3. Prerrequisitos

- [ ] Python 3.9+ disponible (`python --version`)
- [ ] Acceso de lectura a la BD origen (PostgreSQL DOME v1)
- [ ] Acceso de escritura a la BD destino (PostgreSQL EBW)
- [ ] Los usuarios ya están migrados en `wallet_user` **antes** de ejecutar los SQL  
  ⚠️ Si `wallet_user` está vacío, los INSERTs fallan por `NOT NULL` / FK violation en `user_id` y `holder_id`
- [ ] `TARGET_REALM` actualizado en `joiner.py` para el entorno correspondiente (ver sección 4.2)

---

## 4. Paso a paso

### 4.1 Exportar datos del sistema origen

Hay tres fuentes de datos a exportar, cada una de un sistema distinto.

#### vault_keys.csv — claves privadas del vault

Acceder al vault y ejecutar el comando de extracción de claves:

```
echo "did_key,jwk_d,jwk_x,jwk_y,jwk_kty,jwk_crv,jwk_alg" > vault_keys.csv

while IFS= read -r key; do
    [ -z "$key" ] && continue
    echo "$key" | grep -q "^did:key:" || continue
    
    raw=$(kubectl exec wallet-vault-server-0 -n in2 -- \
      vault kv get kv/data/"$key" 2>/dev/null)
    
    json=$(echo "$raw" | grep -o '{[^}]*}')
    
    d=$(echo "$json" | grep -o '"d":"[^"]*"' | sed 's/"d":"//;s/"//')
    x=$(echo "$json" | grep -o '"x":"[^"]*"' | sed 's/"x":"//;s/"//')
    y=$(echo "$json" | grep -o '"y":"[^"]*"' | sed 's/"y":"//;s/"//')
    kty=$(echo "$json" | grep -o '"kty":"[^"]*"' | sed 's/"kty":"//;s/"//')
    crv=$(echo "$json" | grep -o '"crv":"[^"]*"' | sed 's/"crv":"//;s/"//')
    alg=$(echo "$json" | grep -o '"alg":"[^"]*"' | sed 's/"alg":"//;s/"//')
    
    echo "─────────────────────────────────────────"
    echo "DID:     $key"
    echo "JWK:     <redacted>"
    
    echo "$key,$d,$x,$y,$kty,$crv,$alg" >> vault_keys.csv
done < all_keys.txt

echo "═════════════════════════════════════════"
echo "CSV generado: vault_keys.csv"
echo "Total claves procesadas: $(( $(wc -l < vault_keys.csv) - 1 ))"
```

El fichero resultante debe tener estas columnas:
```
did_key, jwk_d, jwk_x, jwk_y, jwk_kty, jwk_crv, jwk_alg
```

#### credentials.csv — credenciales verificables

BD origen · schema `identity` · base de datos `wallet` · tabla `credential`

```sql
COPY (
    SELECT id                AS credential_db_id,
           external_id       AS credential_id,
           user_id           AS old_user_id,
           type              AS credential_type,
           status            AS credential_status,
           format            AS credential_format,
           credential_data,
           json_vc,
           created_at        AS credential_created_at,
           updated_at        AS credential_updated_at
    FROM wallet.credential
) TO '/tmp/credentials.csv' CSV HEADER;
```

#### user_entity.csv — usuarios del sistema origen

BD origen · schema `iam` / `public` · tabla `user_entity`

```sql
COPY (
    SELECT id, email, first_name, last_name, username, realm_id, created_timestamp
    FROM public.user_entity
) TO '/tmp/user_entity.csv' CSV HEADER;
```

Coloca los tres CSV en el mismo directorio que los scripts.

### 4.2 Configurar entorno y generar unified_data.csv

**Antes de ejecutar**, actualizar `TARGET_REALM` en `joiner.py` con el realm del Keycloak origen del entorno correspondiente:

```python
# joiner.py — línea ~27
TARGET_REALM = 'bf013390-0d36-4d69-b775-b8b47a4df472'  # SBX
# TARGET_REALM = '<realm_id de producción>'             # PRD
```

Para obtener el valor correcto:
```sql
-- Ejecutar en la BD Keycloak origen
SELECT id, name FROM realm;
```

Luego ejecutar:
```bash
python joiner.py
```

**Salida esperada (los números varían según el entorno):**
```
[vault_keys] 155 claves cargadas.
[users] 85 registros por ID, 36 emails únicos indexados.
[output] unified_data.csv escrito.

RESUMEN
  Total filas procesadas        :    234
  credential_status=VALID       :    141

  vault_key_found=True          :    155
  vault_key_found=False         :     79

  Usuario encontrado (total)    :    198
    · por user_id (directo)     :    184
    · por email  (fallback)     :     14
  Usuario NO encontrado         :     36
```

Revisa `unified_data.csv`. Columnas clave:
- `vault_key_found` — `True` si existe clave en vault para esa credencial
- `user_found` — `True` si se localizó el usuario por email o por ID

### 4.3 Generar SQL de migración

```bash
python generate_migration.py
```

**Salida esperada:**
```
[mode] Usando unified_data.csv.
[output] migration_private_keys.sql escrito con 70 INSERT(s).
[output] migration_credentials.sql escrito con 100 INSERT(s).
[output] skipped.csv escrito con 134 fila(s).

RESUMEN DE MIGRACIÓN
  Total filas leídas                        :    234
  Credenciales con status VALID             :    100
  INSERTs holder_key  (migration_private_keys.sql)       :     70
  INSERTs wallet_credential (total)         :    100
    · persona  (holder_key via subquery)    :     70
    · máquina  (holder_key_id = NULL)       :     30
  Total skipped                             :    134
```

Revisa `skipped.csv` antes de continuar (ver sección 6).

### 4.4 Migrar usuarios (prerrequisito crítico)

Antes de ejecutar los SQL generados, asegúrate de que `wallet_user` en el destino ya contiene los usuarios correspondientes. El script resuelve `user_id` y `holder_id` en tiempo de INSERT mediante:

```sql
(SELECT id FROM wallet_user WHERE email = '...' LIMIT 1)
```

Si el usuario no existe, el INSERT fallará con:
```
ERROR: null value in column "user_id" violates not-null constraint
```

### 4.5 Ejecutar migration_private_keys.sql (holder_key)

Abrir `migration_private_keys.sql` en pgAdmin o DBeaver, copiar el contenido completo y ejecutarlo contra la BD destino.

Alternativa por terminal:
```bash
psql -h <host> -U <user> -d <database> -f migration_private_keys.sql
```

Verificación rápida:
```sql
SELECT COUNT(*) FROM dome_business_wallet.holder_key;
-- Debe coincidir con el número de INSERTs del resumen
```

### 4.6 Ejecutar migration_credentials.sql (wallet_credential)

Abrir `migration_credentials.sql` en pgAdmin o DBeaver, copiar el contenido completo y ejecutarlo contra la BD destino.

Alternativa por terminal:
```bash
psql -h <host> -U <user> -d <database> -f migration_credentials.sql
```

Verificación rápida:
```sql
SELECT COUNT(*), holder_key_id IS NULL AS is_machine
FROM dome_business_wallet.wallet_credential
GROUP BY is_machine;
-- is_machine=false → numero credenciales de persona
-- is_machine=true  → numero credenciales de máquina
```

---

## 5. Validación post-migración

```sql
-- 1. Comprobar que no hay holder_key sin usuario resuelto
SELECT COUNT(*) FROM dome_business_wallet.holder_key
WHERE holder_id IS NULL;
-- Debe ser 0

-- 2. Comprobar que no hay wallet_credential sin usuario resuelto
SELECT COUNT(*) FROM dome_business_wallet.wallet_credential
WHERE user_id IS NULL;
-- Debe ser 0

-- 3. Comprobar integridad holder_key ↔ wallet_credential (credenciales de persona)
SELECT COUNT(*)
FROM dome_business_wallet.wallet_credential wc
LEFT JOIN dome_business_wallet.holder_key hk ON hk.key_id = wc.holder_key_id
WHERE wc.holder_key_id IS NOT NULL AND hk.key_id IS NULL;
-- Debe ser 0

-- 4. Distribución por tipo
SELECT credential_config_id, COUNT(*)
FROM dome_business_wallet.wallet_credential
GROUP BY credential_config_id;

-- 5. Verificar longitud de clave privada (debe ser 32 bytes)
SELECT COUNT(*) FROM dome_business_wallet.holder_key
WHERE octet_length(private_key) != 32;
-- Debe ser 0
```

---

## 6. Motivos de skip conocidos

Estos son los patrones esperados en `skipped.csv`. No requieren acción salvo que el volumen sea inesperado.

| Motivo | Descripción | Acción |
|---|---|---|
| `credential_status='EXPIRED'` | Credencial caducada — no se migra por diseño | Ninguna |
| `credential_status='REVOKED'` | Credencial revocada | Ninguna |
| `credential_status='ISSUED'` | En proceso de emisión, nunca completada | Revisar si alguna debe migrarse |
| `vault_key_found=False` | Credencial de persona sin clave en vault | Investigar si debería tenerla |
| `jwk_d vacío` | Entrada en vault sin clave privada (datos corruptos) | Revisar en vault origen |
| `Campos NOT NULL vacíos: credential_raw` | Sin JWT en `credential_data` (credenciales v1 pre-JWT) | No migrable sin JWT |
| `Campos NOT NULL vacíos: kid,issuer,...` | JWT no parseable o campos no extraíbles | Revisar JWT en BD origen |

---

## 7. Errores frecuentes y soluciones

### ERROR: null value in column "user_id" violates not-null constraint
**Causa:** Los usuarios no están en `wallet_user` aún.  
**Solución:** Ejecutar la migración de usuarios primero y luego volver a ejecutar los SQL.

### ERROR: null value in column "holder_id" violates not-null constraint
**Causa:** Igual que el anterior — `wallet_user` no tiene el email correspondiente.  
**Solución:** Verificar que el email del usuario existe en `wallet_user`. Si el email cambió, actualizar `unified_data.csv` columna `user_email` y regenerar.

### ERROR: duplicate key value violates unique constraint "uq_holder_key_tenant_holder_credential"
**Causa:** Se está ejecutando el SQL por segunda vez (la clave ya existe).  
**Solución:** Normal si es una re-ejecución. Los INSERTs tienen `ON CONFLICT DO NOTHING`, por lo que es idempotente. Ignorar.

### ERROR: value too long for type character varying(512) — columna kid
**Causa:** El `did:key` del JWT supera 512 caracteres.  
**Solución:** Revisar el JWT de esa credencial. En condiciones normales los `did:key` de P-256 no superan 150 chars.

### ERROR: invalid input syntax for type uuid
**Causa:** El `credential_id` tiene un formato inesperado (no UUID ni `urn:uuid:`).  
**Solución:** Revisar el valor en `unified_data.csv`. Si tiene otro prefijo, añadirlo a `_clean_uuid()` en `generate_migration.py`.

### Todos los INSERTs de holder_key son ON CONFLICT DO NOTHING (0 filas insertadas)
**Causa:** Los datos ya existen del tenant/holder/credential. Puede ocurrir en re-ejecuciones.  
**Solución:** Si es una migración limpia, verificar que el schema está vacío antes de ejecutar. Si es intencional, ignorar.

### FileNotFoundError: No such file or directory: 'vault_keys.csv' (u otro CSV)
**Causa:** Los ficheros CSV no están en la ubicación esperada por los scripts.  
**Solución:** Verificar que la estructura de carpetas es exactamente:
```
dev-tools/
└── scripts/
    └── dome-migration/
        ├── vault_keys.csv
        ├── credentials.csv
        ├── user_entity.csv
        ├── joiner.py
        └── generate_migration.py
```
Los scripts deben ejecutarse **desde el directorio `dome-migration/`**, no desde una subcarpeta:
```bash
cd dev-tools/scripts/dome-migration
python joiner.py          # ✓
python generate_migration.py  # ✓
```

### El script termina sin error pero migration_private_keys.sql tiene 0 INSERTs
**Causa:** `generate_migration.py` leyó `unified_data.csv` vacío o de una ubicación incorrecta.  
**Solución:** Confirmar que `unified_data.csv` existe y tiene filas (`wc -l unified_data.csv` debe ser > 1). Si no existe, ejecutar primero `python joiner.py`.

---

## 8. Rollback

Si la migración falla a mitad y hay que revertir, usar siempre el **rollback seguro por IDs**. Nunca usar TRUNCATE si la tabla puede contener datos previos o datos creados por usuarios reales después de la migración.

### Rollback seguro 

El script genera automáticamente un .sql con todos los DELETEs necesarios para revertir la migración.
Abrir `rollback.sql` en pgAdmin o DBeaver, copiar el contenido completo y ejecutarlo contra la BD destino.

Alternativa por terminal:
```bash
# Abrir rollback.sql en pgAdmin/DBeaver y ejecutar, o por terminal:
psql -h <host> -U <user> -d <database> -f rollback.sql
```

El fichero tiene este aspecto:
```sql
-- Step 1: remove migrated credentials
DELETE FROM dome_business_wallet.wallet_credential
WHERE id IN (
    'a2a16f4f-fd92-4269-b893-b380ee2f08ac',
    '176ecdd4-8f82-41ea-982c-4b06d12596e2',
    ...
);

-- Step 2: remove migrated holder keys
DELETE FROM dome_business_wallet.holder_key
WHERE credential_id IN (
    'a2a16f4f-fd92-4269-b893-b380ee2f08ac',
    ...
);
```

---

## 9. Orden de ejecución resumido

```
1. Exportar vault_keys.csv, credentials.csv y user_entity.csv del sistema origen
2. Actualizar TARGET_REALM en joiner.py para el entorno (SBX / PRD)
3. python joiner.py           → genera unified_data.csv
4. Revisar RESUMEN de joiner  → confirmar vault_key_found y usuario encontrado
5. python generate_migration.py → genera migration_private_keys.sql,
                                   migration_credentials.sql, rollback.sql
6. Revisar skipped.csv        → confirmar que los skips son esperados
7. *** MIGRAR USUARIOS → wallet_user debe estar poblado ***
8. Abrir migration_private_keys.sql en pgAdmin/DBeaver y ejecutar → holder_key
9. Abrir migration_credentials.sql en pgAdmin/DBeaver y ejecutar  → wallet_credential
10. Ejecutar queries de validación (sección 5)
```
