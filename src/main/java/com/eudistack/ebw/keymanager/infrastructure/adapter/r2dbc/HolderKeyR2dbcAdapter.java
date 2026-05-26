package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.HolderKey;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyReadPort;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyWritePort;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.entity.HolderKeyEntity;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.spring.SpringHolderKeyRepository;
import io.r2dbc.postgresql.codec.Json;
import reactor.core.publisher.Mono;

public class HolderKeyR2dbcAdapter implements HolderKeyReadPort, HolderKeyWritePort {

    private final SpringHolderKeyRepository repository;

    public HolderKeyR2dbcAdapter(SpringHolderKeyRepository repository) {
        this.repository = repository;
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
        return new HolderKey(
                entity.getKeyId(),
                entity.getHolderId(),
                entity.getCredentialId(),
                entity.getTenantId(),
                entity.getEncryptedPrivateKey(),
                entity.getPublicJwk().asString(),
                entity.getAlgorithm(),
                CredentialFormat.fromValue(entity.getFormat()),
                entity.getCreatedAt(),
                entity.getRevokedAt()
        );
    }

    private HolderKeyEntity toEntity(HolderKey domain) {
        var entity = new HolderKeyEntity();
        entity.setKeyId(domain.keyId());
        entity.setHolderId(domain.holderId());
        entity.setCredentialId(domain.credentialId());
        entity.setTenantId(domain.tenantId());
        entity.setEncryptedPrivateKey(domain.encryptedPrivateKey());
        entity.setPublicJwk(Json.of(domain.publicJwk()));
        entity.setAlgorithm(domain.algorithm());
        entity.setFormat(domain.format().getValue());
        entity.setCreatedAt(domain.createdAt());
        entity.setRevokedAt(domain.revokedAt());
        return entity;
    }
}