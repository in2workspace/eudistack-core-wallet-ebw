package com.eudistack.ebw.keymanager.infrastructure.adapter.service;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.keymanager.application.PrepareSignUseCase;
import com.eudistack.ebw.keymanager.application.SubmitSignedUseCase;
import com.eudistack.ebw.keymanager.domain.exception.UnsupportedCredentialFormatException;
import com.eudistack.ebw.keymanager.domain.model.GenerateHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyResult;
import com.eudistack.ebw.keymanager.domain.model.PrepareSignRequest;
import com.eudistack.ebw.keymanager.domain.model.PrepareSignResponse;
import com.eudistack.ebw.keymanager.domain.model.SignHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.SignHolderKeyResult;
import com.eudistack.ebw.keymanager.domain.model.SubmitSignedAssertionRequest;
import com.eudistack.ebw.keymanager.domain.model.SubmitSignedAssertionResponse;
import com.eudistack.ebw.keymanager.domain.port.KeyManagerPort;
import com.eudistack.ebw.keymanager.infrastructure.observability.HybridSignTelemetry;
import reactor.core.publisher.Mono;

import java.util.Set;
import java.util.UUID;

/**
 * Hybrid (Passkey PRF) implementation of {@link KeyManagerPort}.
 *
 * <p>US-01 (EUDISTACK-533) delivered the skeleton and format allow-list validation.
 * US-04 (EUDISTACK-536) wires the full signing handshake: {@link #prepareSign} delegates to
 * {@link PrepareSignUseCase} and {@link #submitSignedAssertion} delegates to
 * {@link SubmitSignedUseCase}. Telemetry (OTEL spans + Micrometer metrics) is attached here
 * via {@link HybridSignTelemetry} using {@code doOnSuccess}/{@code doOnError} hooks inside a
 * {@code Mono.deferContextual} so {@code holderId} is read from context at subscription time
 * (NFR-S-536-03, NFR-S-536-04).</p>
 *
 * <p>Key generation ({@link #generateHolderKey}) is not applicable for the hybrid adapter —
 * key wrapping happens client-side during onboarding (US-02, EUDISTACK-534).</p>
 *
 * <p>Spec: EUDISTACK-474 FR-01..FR-04, AC-01, AC-03..AC-05, AC-09;
 * EUDISTACK-536 NFR-S-536-03, NFR-S-536-04; architecture.md §5.1, §6.1, §8.2.</p>
 */
public class HybridKeyManagerAdapter implements KeyManagerPort {

    private static final Set<String> SUPPORTED_FORMATS = Set.of(
            "vc+sd-jwt",    // SD-JWT VC presentation format identifier (OID4VP, AC-05)
            "jwt_vc_json"   // VC-JWT presentation format identifier (AC-05)
    );

    private final PrepareSignUseCase prepareSignUseCase;
    private final SubmitSignedUseCase submitSignedUseCase;
    private final HybridSignTelemetry telemetry;

    public HybridKeyManagerAdapter(PrepareSignUseCase prepareSignUseCase,
                                    SubmitSignedUseCase submitSignedUseCase,
                                    HybridSignTelemetry telemetry) {
        this.prepareSignUseCase = prepareSignUseCase;
        this.submitSignedUseCase = submitSignedUseCase;
        this.telemetry = telemetry;
    }

    @Override
    public Mono<HolderKeyResult> generateHolderKey(GenerateHolderKeyCommand command) {
        return Mono.error(new UnsupportedOperationException(
                "generateHolderKey is not applicable for the hybrid adapter — use the onboarding flow."));
    }

    @Override
    public Mono<SignHolderKeyResult> signWithHolderKey(SignHolderKeyCommand cmd) {
        return Mono.error(new UnsupportedOperationException(
                "signWithHolderKey is not applicable for the hybrid adapter — use prepareSign/submitSignedAssertion."));
    }

    @Override
    public Mono<PrepareSignResponse> prepareSign(PrepareSignRequest request) {
        if (!SUPPORTED_FORMATS.contains(request.format())) {
            return Mono.error(new UnsupportedCredentialFormatException(request.format()));
        }
        return Mono.deferContextual(ctx -> {
            String holderId = ctx.getOrDefault(ReactorContextKeys.HOLDER_ID, "");
            String correlationId = UUID.randomUUID().toString();
            long startNanos = System.nanoTime();
            return prepareSignUseCase.execute(request, correlationId)
                    .doOnSuccess(r -> telemetry.recordPrepareSuccess(r.correlationId(), holderId, startNanos))
                    .doOnError(ex -> telemetry.recordPrepareError(correlationId, holderId, ex, startNanos));
        });
    }

    @Override
    public Mono<SubmitSignedAssertionResponse> submitSignedAssertion(SubmitSignedAssertionRequest request) {
        return Mono.deferContextual(ctx -> {
            String holderId = ctx.getOrDefault(ReactorContextKeys.HOLDER_ID, "");
            long startNanos = System.nanoTime();
            return submitSignedUseCase.execute(request)
                    .doOnSuccess(r -> telemetry.recordSubmitSuccess(request.correlationId(), holderId, startNanos))
                    .doOnError(ex -> telemetry.recordSubmitError(request.correlationId(), holderId, ex, startNanos));
        });
    }
}
