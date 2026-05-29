package com.eudistack.ebw.keymanager.domain.port;

import com.eudistack.ebw.keymanager.domain.model.HolderKey;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyId;
import reactor.core.publisher.Mono;

/**
 * Read port for holder key lookup.
 *
 * <p>Two distinct lookup strategies are supported:
 * <ul>
 *   <li>{@link #findBy(String, String, String)} — natural composite key lookup used in key
 *       generation (US-02). Kept for backward-compat and internal use.</li>
 *   <li>{@link #findById(String, String, HolderKeyId)} — surrogate-key lookup used in the signing
 *       path (US-03). The consumer provides the opaque {@code keyId} received during
 *       credential issuance (AD-407-4). Includes {@code holderId} to prevent intra-tenant
 *       IDOR (AC-05/F1).</li>
 * </ul>
 *
 * <p>Both methods return {@code empty()} when no active (non-revoked) key is found.
 * The query must filter {@code WHERE revoked_at IS NULL}.</p>
 *
 * <p>Spec: ADR-021, EUDISTACK-119 EC-01, EUDISTACK-407 AC-06, EC-01, AD-407-4.</p>
 */
public interface HolderKeyReadPort {

    /**
     * Looks up the active holder key by the natural composite key
     * {@code (tenantId, holderId, credentialId)}.
     *
     * @param tenantId     the tenant that owns the key
     * @param holderId     the wallet holder identifier
     * @param credentialId the credential identifier
     * @return an active, non-revoked key; {@code empty()} if not found or revoked
     */
    Mono<HolderKey> findBy(String tenantId, String holderId, String credentialId);

    /**
     * Looks up the active holder key by surrogate key {@code keyId} for the given tenant
     * and holder.
     *
     * <p>All three dimensions are included in the WHERE clause:
     * <ul>
     *   <li>Tenant isolation — a key belonging to another tenant is invisible (ADR-025).</li>
     *   <li>Holder isolation — a key belonging to another holder within the same tenant is
     *       treated identically to a missing key, preventing intra-tenant IDOR (AC-05/F1).</li>
     * </ul>
     * A caller that supplies the correct tenant but a wrong holder will receive
     * {@code empty()}, which enters the opaque rejection path indistinguishably
     * from "key not found".</p>
     *
     * @param tenantId the tenant that must own the key
     * @param holderId the holder who must own the key within that tenant
     * @param keyId    the surrogate identifier returned during key generation
     * @return an active, non-revoked key; {@code empty()} if not found, revoked,
     *         belonging to a different tenant, or belonging to a different holder
     */
    Mono<HolderKey> findById(String tenantId, String holderId, HolderKeyId keyId);
}
