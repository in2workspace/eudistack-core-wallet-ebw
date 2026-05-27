package com.eudistack.ebw.keymanager.infrastructure.adapter.service;

import com.eudistack.ebw.keymanager.application.GenerateHolderKeyUseCase;
import com.eudistack.ebw.keymanager.domain.model.GenerateHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyResult;
import com.eudistack.ebw.keymanager.domain.port.KeyManagerPort;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Implements {@link KeyManagerPort} by delegating to {@link GenerateHolderKeyUseCase}
 * and enforcing the end-to-end latency budget (NFR-P-119-01).
 *
 * <p>The 2 500 ms timeout covers the entire reactive chain: algorithm negotiation,
 * key generation, UPSERT, JWS signing, and audit emission. On timeout, the Mono
 * terminates with {@link reactor.core.Exceptions#isTimeout}; the HTTP adapter
 * maps this to 503 Service Unavailable (T7).</p>
 *
 * <p>Spec: EUDISTACK-119 NFR-P-119-01, AD-119-2.</p>
 */
public class DbKeyManagerService implements KeyManagerPort {

    static final Duration TIMEOUT = Duration.ofMillis(2500);

    private final GenerateHolderKeyUseCase useCase;

    public DbKeyManagerService(GenerateHolderKeyUseCase useCase) {
        this.useCase = useCase;
    }

    @Override
    public Mono<HolderKeyResult> generateHolderKey(GenerateHolderKeyCommand command) {
        return useCase.execute(command).timeout(TIMEOUT);
    }
}