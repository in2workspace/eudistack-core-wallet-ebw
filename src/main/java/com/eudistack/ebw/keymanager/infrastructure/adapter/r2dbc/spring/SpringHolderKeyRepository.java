package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.spring;

import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.entity.HolderKeyEntity;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

public interface SpringHolderKeyRepository extends ReactiveCrudRepository<HolderKeyEntity, String> {

    Mono<HolderKeyEntity> findFirstByTenantIdAndHolderIdAndCredentialIdAndRevokedAtIsNull(
            String tenantId, String holderId, String credentialId);

    /**
     * Looks up a non-revoked holder key by tenant, holder, and surrogate key identifier.
     *
     * <p>All three dimensions are in the WHERE clause:
     * <ul>
     *   <li>Tenant — cross-tenant isolation (ADR-025).</li>
     *   <li>Holder — intra-tenant IDOR prevention (AC-05/F1).</li>
     *   <li>Key ID — surrogate identity lookup.</li>
     * </ul>
     * A key that exists but belongs to a different holder returns {@code empty()},
     * which is indistinguishable from a missing key to the caller.</p>
     *
     * @param tenantId the tenant that must own the key
     * @param holderId the holder who must own the key within that tenant
     * @param keyId    the UUID value of the surrogate key
     * @return the entity if found, not revoked, and owned by the given holder; empty otherwise
     */
    Mono<HolderKeyEntity> findFirstByTenantIdAndHolderIdAndKeyIdAndRevokedAtIsNull(
            String tenantId, String holderId, String keyId);
}