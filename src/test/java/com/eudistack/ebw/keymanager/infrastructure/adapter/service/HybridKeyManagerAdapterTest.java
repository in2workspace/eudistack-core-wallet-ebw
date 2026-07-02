package com.eudistack.ebw.keymanager.infrastructure.adapter.service;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.keymanager.application.PrepareSignUseCase;
import com.eudistack.ebw.keymanager.application.SubmitSignedUseCase;
import com.eudistack.ebw.keymanager.domain.exception.UnsupportedCredentialFormatException;
import com.eudistack.ebw.keymanager.domain.model.PrepareSignRequest;
import com.eudistack.ebw.keymanager.domain.model.PrepareSignResponse;
import com.eudistack.ebw.keymanager.infrastructure.observability.HybridSignTelemetry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link HybridKeyManagerAdapter} format allow-list validation and delegation.
 *
 * <p>Spec: EUDISTACK-533 AC-05, ES-01; EUDISTACK-536 AC-01.</p>
 */
@ExtendWith(MockitoExtension.class)
class HybridKeyManagerAdapterTest {

    @Mock private PrepareSignUseCase prepareSignUseCase;
    @Mock private SubmitSignedUseCase submitSignedUseCase;
    @Mock private HybridSignTelemetry telemetry;

    private HybridKeyManagerAdapter adapter;

    @BeforeEach
    void setUp() {
        adapter = new HybridKeyManagerAdapter(prepareSignUseCase, submitSignedUseCase, telemetry);
    }

    // --- AC-05 / ES-01: unsupported formats are rejected before reaching the use case ---

    @Test
    void prepareSign_unsupportedFormat_jwtVcJsonLd_throwsBeforeUseCase() {
        StepVerifier.create(adapter.prepareSign(new PrepareSignRequest("c", "ch", "jwt_vc_json-ld")))
                .expectErrorMatches(ex -> ex instanceof UnsupportedCredentialFormatException
                        && ex.getMessage().contains("jwt_vc_json-ld"))
                .verify();
    }

    @Test
    void prepareSign_unsupportedFormat_msoMdoc_throwsBeforeUseCase() {
        StepVerifier.create(adapter.prepareSign(new PrepareSignRequest("c", "ch", "mso_mdoc")))
                .expectError(UnsupportedCredentialFormatException.class)
                .verify();
    }

    @Test
    void prepareSign_unsupportedFormat_applicationVc_throwsBeforeUseCase() {
        StepVerifier.create(adapter.prepareSign(new PrepareSignRequest("c", "ch", "application/vc")))
                .expectError(UnsupportedCredentialFormatException.class)
                .verify();
    }

    // --- AC-05: supported formats bypass the allow-list and delegate to the use case ---

    @Test
    void prepareSign_vcSdJwt_passesAllowListAndDelegatesToUseCase() {
        PrepareSignResponse mockResponse = new PrepareSignResponse(
                "salt", "blob", "iv", "tag", "{}", "header.payload", "corr-id");
        when(prepareSignUseCase.execute(any(), any())).thenReturn(Mono.just(mockResponse));

        StepVerifier.create(adapter.prepareSign(new PrepareSignRequest("c", "ch", "vc+sd-jwt"))
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.HOLDER_ID, "holder")))
                .assertNext(r -> {
                    // Confirmed format validation passed and use case was called
                })
                .verifyComplete();
    }

    @Test
    void prepareSign_jwtVcJson_passesAllowListAndDelegatesToUseCase() {
        PrepareSignResponse mockResponse = new PrepareSignResponse(
                "salt", "blob", "iv", "tag", "{}", "header.payload", "corr-id");
        when(prepareSignUseCase.execute(any(), any())).thenReturn(Mono.just(mockResponse));

        StepVerifier.create(adapter.prepareSign(new PrepareSignRequest("c", "ch", "jwt_vc_json"))
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.HOLDER_ID, "holder")))
                .assertNext(r -> {
                    // Confirmed format validation passed and use case was called
                })
                .verifyComplete();
    }

    // --- generateHolderKey and signWithHolderKey are not applicable for the hybrid adapter ---

    @Test
    void generateHolderKey_alwaysThrowsUnsupportedOperationException() {
        StepVerifier.create(adapter.generateHolderKey(null))
                .expectError(UnsupportedOperationException.class)
                .verify();
    }

    @Test
    void signWithHolderKey_alwaysThrowsUnsupportedOperationException() {
        StepVerifier.create(adapter.signWithHolderKey(null))
                .expectError(UnsupportedOperationException.class)
                .verify();
    }
}
