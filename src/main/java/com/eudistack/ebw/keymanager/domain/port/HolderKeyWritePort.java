package com.eudistack.ebw.keymanager.domain.port;

import com.eudistack.ebw.keymanager.domain.model.HolderKey;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyPersistResult;
import reactor.core.publisher.Mono;

/**
 * Write port for holder key persistence.
 *
 * <p>The single method uses an idempotent upsert semantic: if a key for the same
 * {@code (tenantId, holderId, credentialId)} composite already exists in the store,
 * the existing record is returned with {@code created=false}; otherwise a new row is
 * inserted and {@code created=true} is returned.</p>
 *
 * <p>Full UPSERT-ON-CONFLICT implementation is in the R2DBC adapter (T5).</p>
 *
 * <p>Spec: ADR-021 (key-per-credential), EUDISTACK-119 EC-01.</p>
 */
public interface HolderKeyWritePort {

    Mono<HolderKeyPersistResult> upsertIfAbsent(HolderKey holderKey);
}
