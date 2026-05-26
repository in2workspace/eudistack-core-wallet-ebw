package com.eudistack.ebw.keymanager.domain.port;

import com.eudistack.ebw.keymanager.domain.model.HolderKey;
import reactor.core.publisher.Mono;

/**
 * Read port for holder key lookup.
 *
 * <p>Lookup uses the natural composite key {@code (tenantId, holderId, credentialId)}
 * per ADR-021 (key-per-credential). The query must return only the active (non-revoked) key.</p>
 *
 * <p>Spec: ADR-021, EUDISTACK-119 EC-01.</p>
 */
public interface HolderKeyReadPort {

    Mono<HolderKey> findBy(String tenantId, String holderId, String credentialId);
}