package com.eudistack.ebw.keymanager.domain.port;

import com.eudistack.ebw.keymanager.domain.model.GenerateHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyResult;
import reactor.core.publisher.Mono;

/**
 * Primary port for the Key Manager bounded context.
 *
 * <p>Exposes the key lifecycle operations that the Wallet PWA layer calls.
 * The implementation lives in the application layer ({@code GenerateHolderKeyUseCase}).</p>
 *
 * <p>Spec: EUDISTACK-119, OID4VCI 1.0 §7 (Token Request / Credential Request flow),
 * §8.2 (jwt proof type).</p>
 */
public interface KeyManagerPort {

    Mono<HolderKeyResult> generateHolderKey(GenerateHolderKeyCommand command);

    // sign(...) — pending US-03
}