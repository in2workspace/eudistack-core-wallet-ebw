package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.spring;

import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.entity.HolderKeyEntity;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

public interface SpringHolderKeyRepository extends ReactiveCrudRepository<HolderKeyEntity, String> {

    Mono<HolderKeyEntity> findFirstByTenantIdAndHolderIdAndCredentialIdAndRevokedAtIsNull(
            String tenantId, String holderId, String credentialId);

    /**
     * Looks up a non-revoked holder key by tenant and surrogate key identifier.
     *
     * <p>The tenant is part of the WHERE clause to enforce isolation (ADR-025 — a key
     * belonging to a different tenant must be invisible to the requester).</p>
     *
     * @param tenantId the tenant that must own the key
     * @param keyId    the UUID value of the surrogate key
     * @return the entity if found and not revoked; empty otherwise
     */
    Mono<HolderKeyEntity> findFirstByTenantIdAndKeyIdAndRevokedAtIsNull(
            String tenantId, String keyId);
}