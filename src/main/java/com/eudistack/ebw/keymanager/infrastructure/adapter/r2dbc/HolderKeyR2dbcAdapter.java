package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.HolderKey;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyId;
import com.eudistack.ebw.keymanager.domain.model.JwkPublic;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyReadPort;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyWritePort;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.entity.HolderKeyEntity;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.spring.SpringHolderKeyRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.r2dbc.postgresql.codec.Json;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

/**
 * R2DBC adapter for holder key persistence.
 *
 * <p>This is a minimal adapter stub that compiles against the rewritten {@link HolderKey}
 * domain model (T1). Full UPSERT-ON-CONFLICT logic and the {@code HolderKeyWritePort}
 * signature will be completed in T5.</p>
 *
 * <p>See {@code technical-design.md §3.2} for the complete adapter specification.</p>
 */
public class HolderKeyR2dbcAdapter implements HolderKeyReadPort, HolderKeyWritePort {

    private final SpringHolderKeyRepository repository;
    private final ObjectMapper objectMapper;

    public HolderKeyR2dbcAdapter(SpringHolderKeyRepository repository, ObjectMapper objectMapper) {
        this.repository = repository;
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<HolderKey> findByKeyId(String keyId) {
        return repository.findById(keyId).map(this::toDomain);
    }

    @Override
    public Mono<HolderKey> findActiveByHolderAndCredential(String holderId, String credentialId) {
        return repository.findFirstByHolderIdAndCredentialIdAndRevokedAtIsNull(holderId, credentialId)
                .map(this::toDomain);
    }

    @Override
    public Mono<HolderKey> save(HolderKey holderKey) {
        return repository.save(toEntity(holderKey)).map(this::toDomain);
    }

    private HolderKey toDomain(HolderKeyEntity entity) {
        Map<String, Object> jwkClaims = parseJwk(entity.getPublicJwk());
        return new HolderKey(
                HolderKeyId.of(UUID.fromString(entity.getKeyId())),
                entity.getTenantId(),
                entity.getHolderId(),
                entity.getCredentialId(),
                CredentialFormat.valueOf(entity.getFormat()),
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
        entity.setFormat(domain.format().name());
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