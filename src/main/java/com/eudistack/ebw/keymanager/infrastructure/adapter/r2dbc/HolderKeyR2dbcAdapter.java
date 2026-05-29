package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.HolderKey;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyId;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyPersistResult;
import com.eudistack.ebw.keymanager.domain.model.JwkPublic;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyReadPort;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyWritePort;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.entity.HolderKeyEntity;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.spring.SpringHolderKeyRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.r2dbc.postgresql.codec.Json;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * R2DBC adapter for holder key persistence.
 *
 * <p>UPSERT strategy (EC-01 / ADR-021): {@code INSERT … ON CONFLICT (tenant_id, holder_id, credential_id)
 * DO NOTHING RETURNING key_id}. When the row already exists (conflict), the INSERT produces no
 * RETURNING row and we fall back to a SELECT of the canonical persisted key. This guarantees
 * idempotency under concurrent first-issuance races.</p>
 */
public class HolderKeyR2dbcAdapter implements HolderKeyReadPort, HolderKeyWritePort {

    private static final String UPSERT_SQL =
            "INSERT INTO holder_key " +
            "(key_id, holder_id, credential_id, tenant_id, private_key, public_jwk, algorithm, format, created_at, revoked_at) " +
            "VALUES (:keyId, :holderId, :credentialId, :tenantId, :privateKey, :publicJwk, :algorithm, :format, :createdAt, :revokedAt) " +
            "ON CONFLICT ON CONSTRAINT uq_holder_key_tenant_holder_credential DO NOTHING " +
            "RETURNING key_id";

    private final SpringHolderKeyRepository repository;
    private final ObjectMapper objectMapper;
    private final DatabaseClient databaseClient;

    public HolderKeyR2dbcAdapter(SpringHolderKeyRepository repository,
                                  ObjectMapper objectMapper,
                                  DatabaseClient databaseClient) {
        this.repository = repository;
        this.objectMapper = objectMapper;
        this.databaseClient = databaseClient;
    }

    @Override
    public Mono<HolderKey> findBy(String tenantId, String holderId, String credentialId) {
        return repository.findFirstByTenantIdAndHolderIdAndCredentialIdAndRevokedAtIsNull(
                        tenantId, holderId, credentialId)
                .map(this::toDomain);
    }

    /**
     * Looks up an active holder key by surrogate key identifier.
     *
     * <p>The tenant filter is mandatory per ADR-025 — a key belonging to a different tenant
     * returns {@code empty()}, which is indistinguishable from a missing key to the caller.</p>
     *
     * @param tenantId the tenant that must own the key
     * @param keyId    the surrogate identifier
     * @return the domain entity; {@code empty()} if not found, revoked, or cross-tenant
     */
    @Override
    public Mono<HolderKey> findById(String tenantId, HolderKeyId keyId) {
        return repository.findFirstByTenantIdAndKeyIdAndRevokedAtIsNull(
                        tenantId, keyId.value().toString())
                .map(this::toDomain);
    }

    @Override
    public Mono<HolderKeyPersistResult> upsertIfAbsent(HolderKey holderKey) {
        HolderKeyEntity entity = toEntity(holderKey);

        DatabaseClient.GenericExecuteSpec spec = databaseClient.sql(UPSERT_SQL)
                .bind("keyId", entity.getKeyId())
                .bind("holderId", entity.getHolderId())
                .bind("credentialId", entity.getCredentialId())
                .bind("tenantId", entity.getTenantId())
                .bind("privateKey", entity.getPrivateKey())
                .bind("publicJwk", entity.getPublicJwk())
                .bind("algorithm", entity.getAlgorithm())
                .bind("format", entity.getFormat())
                .bind("createdAt", entity.getCreatedAt());

        spec = entity.getRevokedAt() != null
                ? spec.bind("revokedAt", entity.getRevokedAt())
                : spec.bindNull("revokedAt", Instant.class);

        return spec.map(row -> row.get("key_id", String.class))
                .one()
                // INSERT succeeded — return the domain object we prepared (no extra SELECT needed)
                .map(ignored -> new HolderKeyPersistResult(true, toDomain(entity)))
                // Conflict — fetch the canonical existing row
                .switchIfEmpty(
                        repository.findFirstByTenantIdAndHolderIdAndCredentialIdAndRevokedAtIsNull(
                                        holderKey.tenantId(), holderKey.holderId(), holderKey.credentialId())
                                .map(existing -> new HolderKeyPersistResult(false, toDomain(existing))));
    }

    private HolderKey toDomain(HolderKeyEntity entity) {
        Map<String, Object> jwkClaims = parseJwk(entity.getPublicJwk());
        return new HolderKey(
                HolderKeyId.of(UUID.fromString(entity.getKeyId())),
                entity.getTenantId(),
                entity.getHolderId(),
                entity.getCredentialId(),
                CredentialFormat.fromDbValue(entity.getFormat()),
                KeyAlgorithm.valueOf(entity.getAlgorithm()),
                entity.getPrivateKey(),
                new JwkPublic(jwkClaims),
                entity.getCreatedAt(),
                entity.getRevokedAt()
        );
    }

    private HolderKeyEntity toEntity(HolderKey domain) {
        var entity = new HolderKeyEntity();
        entity.setKeyId(domain.id().value().toString());
        entity.setHolderId(domain.holderId());
        entity.setCredentialId(domain.credentialId());
        entity.setTenantId(domain.tenantId());
        entity.setPrivateKey(domain.privateKey());
        entity.setPublicJwk(Json.of(serializeJwk(domain.publicJwk())));
        entity.setAlgorithm(domain.algorithm().name());
        entity.setFormat(domain.format().dbValue());
        entity.setCreatedAt(domain.createdAt());
        entity.setRevokedAt(domain.revokedAt());
        return entity;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> parseJwk(Json json) {
        try {
            return objectMapper.readValue(json.asString(), new TypeReference<Map<String, Object>>() { });
        } catch (Exception e) {
            throw new IllegalStateException("Failed to deserialize public JWK from database", e);
        }
    }

    private String serializeJwk(JwkPublic jwkPublic) {
        try {
            return objectMapper.writeValueAsString(jwkPublic.claims());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize public JWK for database", e);
        }
    }
}