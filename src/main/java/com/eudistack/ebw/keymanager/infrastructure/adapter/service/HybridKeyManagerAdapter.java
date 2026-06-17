package com.eudistack.ebw.keymanager.infrastructure.adapter.service;

import com.eudistack.ebw.keymanager.domain.exception.UnsupportedCredentialFormatException;
import com.eudistack.ebw.keymanager.domain.model.GenerateHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyResult;
import com.eudistack.ebw.keymanager.domain.model.SignHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.SignHolderKeyResult;
import com.eudistack.ebw.keymanager.domain.port.KeyManagerPort;
import com.eudistack.ebw.keymanager.domain.model.PrepareSignRequest;
import com.eudistack.ebw.keymanager.domain.model.PrepareSignResponse;
import com.eudistack.ebw.keymanager.domain.model.SubmitSignedAssertionRequest;
import com.eudistack.ebw.keymanager.domain.model.SubmitSignedAssertionResponse;
import reactor.core.publisher.Mono;

import java.util.Set;

/**
 * Hybrid (Passkey PRF) implementation of {@link KeyManagerPort}.
 *
 * <p>US-01 (EUDISTACK-533) delivers the skeleton and format allow-list validation.
 * The full handshake logic ({@link #prepareSign} / {@link #submitSignedAssertion}) is
 * implemented in US-04 (EUDISTACK-536).</p>
 *
 * <p>Key generation ({@link #generateHolderKey}) is not applicable for the hybrid adapter —
 * key wrapping happens client-side during onboarding (US-02, EUDISTACK-534).</p>
 *
 * <p>Spec: EUDISTACK-474 FR-01..FR-04, AC-01, AC-03..AC-05, AC-09;
 * architecture.md §5.1 (building blocks) §6.1 (runtime flows).</p>
 */
public class HybridKeyManagerAdapter implements KeyManagerPort {

    private static final Set<String> SUPPORTED_FORMATS = Set.of(
            "vc+sd-jwt",    // SD-JWT VC presentation format identifier (OID4VP, AC-05)
            "jwt_vc_json"   // VC-JWT presentation format identifier (AC-05)
    );

    @Override
    public Mono<HolderKeyResult> generateHolderKey(GenerateHolderKeyCommand command) {
        // TODO(EUDISTACK-534/US-02): hybrid key generation is client-side (Passkey PRF wrap).
        // This entry point is not used; key registration goes through the onboarding endpoint.
        return Mono.error(new UnsupportedOperationException(
                "generateHolderKey is not applicable for the hybrid adapter — use the onboarding flow."));
    }

    @Override
    public Mono<SignHolderKeyResult> signWithHolderKey(SignHolderKeyCommand cmd) {
        // TODO(EUDISTACK-536/US-04): hybrid signing requires the prepareSign/submitSignedAssertion handshake.
        // Direct signWithHolderKey is DB-only; hybrid tenants must call the two-step handshake endpoints.
        return Mono.error(new UnsupportedOperationException(
                "signWithHolderKey is not applicable for the hybrid adapter — use prepareSign/submitSignedAssertion."));
    }

    @Override
    public Mono<PrepareSignResponse> prepareSign(PrepareSignRequest request) {
        if (!SUPPORTED_FORMATS.contains(request.format())) {
            return Mono.error(new UnsupportedCredentialFormatException(request.format()));
        }
        // TODO(EUDISTACK-536/US-04): retrieve prf_salt + wrapped_blob from DB (US-05, EUDISTACK-537)
        // and return PRF challenge metadata to the PWA so it can derive the unwrap key via Passkey PRF.
        return Mono.error(new UnsupportedOperationException(
                "prepareSign skeleton — full implementation in US-04 (EUDISTACK-536)."));
    }

    @Override
    public Mono<SubmitSignedAssertionResponse> submitSignedAssertion(SubmitSignedAssertionRequest request) {
        // TODO(EUDISTACK-536/US-04): verify client's signed assertion against cnf.jwk,
        // unwrap the holder key, and produce the kb+jwt.
        return Mono.error(new UnsupportedOperationException(
                "submitSignedAssertion skeleton — full implementation in US-04 (EUDISTACK-536)."));
    }
}
