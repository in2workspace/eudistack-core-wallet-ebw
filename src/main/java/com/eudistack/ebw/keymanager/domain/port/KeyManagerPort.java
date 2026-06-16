package com.eudistack.ebw.keymanager.domain.port;

import com.eudistack.ebw.keymanager.domain.model.GenerateHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyResult;
import com.eudistack.ebw.keymanager.domain.model.SignHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.SignHolderKeyResult;
import com.eudistack.ebw.keymanager.domain.model.PrepareSignRequest;
import com.eudistack.ebw.keymanager.domain.model.PrepareSignResponse;
import com.eudistack.ebw.keymanager.domain.model.SubmitSignedAssertionRequest;
import com.eudistack.ebw.keymanager.domain.model.SubmitSignedAssertionResponse;
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

    // TODO(EUDISTACK-5): prepareSign/submitSignedAssertion were to be delivered by EUDISTACK-5 SPI contract.
    // Added here as workaround per EUDISTACK-533 R-1 decision (user approved 2026-06-16).

    /**
     * Initiates the hybrid (Passkey PRF) signing handshake.
     *
     * <p>The default implementation rejects with {@link UnsupportedOperationException} so
     * that existing {@link KeyManagerPort} adapters ({@code DbKeyManagerService}) do not need
     * to implement this method — it is only meaningful for {@code HybridKeyManagerAdapter}.</p>
     *
     * <p>Spec: EUDISTACK-533 FR-03, AC-03.</p>
     */
    default Mono<PrepareSignResponse> prepareSign(PrepareSignRequest request) {
        return Mono.error(new UnsupportedOperationException(
                "prepareSign not supported for this key manager type. Use signWithHolderKey instead."));
    }

    /**
     * Finalises the hybrid signing handshake and produces the key-binding JWT.
     *
     * <p>The default implementation rejects with {@link UnsupportedOperationException} so
     * that existing {@link KeyManagerPort} adapters do not need to implement this method.</p>
     *
     * <p>Spec: EUDISTACK-533 FR-03, AC-04.</p>
     */
    default Mono<SubmitSignedAssertionResponse> submitSignedAssertion(SubmitSignedAssertionRequest request) {
        return Mono.error(new UnsupportedOperationException(
                "submitSignedAssertion not supported for this key manager type. Use signWithHolderKey instead."));
    }
}
