package com.eudistack.ebw.domain.repository;

import com.eudistack.ebw.domain.model.WalletActivity;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface WalletActivityRepository {

    /**
     * Insert the activity row if its id does not already exist. Emits the persisted
     * activity when a new row was actually inserted; completes empty when a row with
     * that id already existed (no-op). Idempotent by design so devices can safely
     * retry/replay the same sync event without side effects.
     */
    Mono<WalletActivity> insertIfAbsent(WalletActivity activity);

    Flux<WalletActivity> findRecentByUserId(UUID userId, int limit);
}
