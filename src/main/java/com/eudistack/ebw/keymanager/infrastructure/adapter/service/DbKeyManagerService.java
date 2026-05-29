package com.eudistack.ebw.keymanager.infrastructure.adapter.service;

import com.eudistack.ebw.keymanager.application.GenerateHolderKeyUseCase;
import com.eudistack.ebw.keymanager.application.SignHolderKeyUseCase;
import com.eudistack.ebw.keymanager.domain.model.GenerateHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyResult;
import com.eudistack.ebw.keymanager.domain.model.SignHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.SignHolderKeyResult;
import com.eudistack.ebw.keymanager.domain.port.KeyManagerPort;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Implements {@link KeyManagerPort} by delegating to:
 * <ul>
 *   <li>{@link GenerateHolderKeyUseCase} for key generation (US-02)</li>
 *   <li>{@link SignHolderKeyUseCase} for server-side signing (US-03)</li>
 * </ul>
 *
 * <p>The 2 500 ms timeout for key generation covers the entire reactive chain: algorithm
 * negotiation, key generation, UPSERT, JWS signing, and audit emission (NFR-P-119-01).
 * The signing use case manages its own timeout internally (NFR-S-407-07).</p>
 *
 * <p>Spec: EUDISTACK-119 NFR-P-119-01, AD-119-2. EUDISTACK-407 ES-05, NFR-S-407-07.</p>
 */
public class DbKeyManagerService implements KeyManagerPort {

    static final Duration GENERATE_TIMEOUT = Duration.ofMillis(2500);

    private final GenerateHolderKeyUseCase generateUseCase;
    private final SignHolderKeyUseCase signUseCase;

    public DbKeyManagerService(GenerateHolderKeyUseCase generateUseCase,
                                SignHolderKeyUseCase signUseCase) {
        this.generateUseCase = generateUseCase;
        this.signUseCase = signUseCase;
    }

    @Override
    public Mono<HolderKeyResult> generateHolderKey(GenerateHolderKeyCommand command) {
        return generateUseCase.execute(command).timeout(GENERATE_TIMEOUT);
    }

    @Override
    public Mono<SignHolderKeyResult> signWithHolderKey(SignHolderKeyCommand cmd) {
        // The outer timeout is managed by SignHolderKeyUseCase.execute() itself
        return signUseCase.execute(cmd);
    }
}
