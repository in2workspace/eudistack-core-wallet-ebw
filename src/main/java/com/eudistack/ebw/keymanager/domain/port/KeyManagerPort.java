package com.eudistack.ebw.keymanager.domain.port;

import com.eudistack.ebw.keymanager.domain.model.GenerateHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyResult;
import com.eudistack.ebw.keymanager.domain.model.SignHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.SignHolderKeyResult;
import reactor.core.publisher.Mono;

/**
 * Primary port for the Key Manager bounded context.
 *
 * <p>Exposes the key lifecycle operations that the Wallet PWA layer calls.
 * The implementation lives in the application layer ({@code GenerateHolderKeyUseCase}
 * for key generation; {@code SignHolderKeyUseCase} for signing).</p>
 *
 * <p>Spec: EUDISTACK-119 (generateHolderKey), EUDISTACK-407 (signWithHolderKey),
 * OID4VCI 1.0 §7 (Token Request / Credential Request flow), §8.2 (jwt proof type),
 * RFC 9901 §4.1.2 (kb+jwt), OID4VP §B.1 (VP envelope).</p>
 */
public interface KeyManagerPort {

    Mono<HolderKeyResult> generateHolderKey(GenerateHolderKeyCommand command);

    /**
     * Signs {@code signingInput} with the holder key identified by {@code cmd.keyId()}.
     *
     * <p>The signing type determines the JWS {@code typ} header value:
     * {@code kb+jwt} for {@code KB_JWT} or {@code vp+jwt} for {@code VP_ENVELOPE}.
     * The EBW treats {@code signingInput} as opaque bytes — it does NOT parse or validate
     * the semantic structure (EC-03). That responsibility belongs to the consumer.</p>
     *
     * <p>All rejection paths (key not found, key revoked, cross-tenant) produce an opaque
     * constant-time response per ADR-025.</p>
     *
     * @param cmd the signing command; must not be null
     * @return a {@code Mono} emitting the signed JWS result, or terminating with a
     *         domain exception on rejection
     */
    Mono<SignHolderKeyResult> signWithHolderKey(SignHolderKeyCommand cmd);
}
