package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.keymanager.domain.exception.HolderIsolationViolationException;
import com.eudistack.ebw.keymanager.domain.exception.PrfSaltNotFoundException;
import com.eudistack.ebw.keymanager.domain.model.PrepareSignRequest;
import com.eudistack.ebw.keymanager.domain.model.PrepareSignResponse;
import com.eudistack.ebw.keymanager.domain.model.WrappedKeyHandle;
import com.eudistack.ebw.keymanager.domain.port.WrappedKeyHandleRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PrepareSignUseCase}.
 *
 * <p>Tests cover material resolution, signing_input assembly, correlation_id generation,
 * holder isolation, and reactive error propagation. The PRF salt and wrapped-blob contents
 * are opaque test fixtures — the use case treats them as bytes without inspecting them.</p>
 *
 * <p>Spec: EUDISTACK-536 AC-01, AC-03, AC-08, EC-03, ES-02, ES-04, ES-06,
 * NFR-S-536-01, NFR-S-536-02.</p>
 */
@ExtendWith(MockitoExtension.class)
class PrepareSignUseCaseTest {

    private static final String TENANT  = "sandbox";
    private static final String HOLDER  = "holder-uuid-1";
    private static final String CRED_ID = "cred-id-1";
    private static final String CHALLENGE = "test-vp-challenge-abc";
    private static final String FORMAT  = "vc+sd-jwt";

    private static final byte[] PRF_SALT    = new byte[32];
    private static final byte[] BLOB_BYTES  = new byte[48];
    private static final byte[] IV_BYTES    = new byte[12];
    private static final byte[] TAG_BYTES   = new byte[16];
    private static final String CNF_JWK = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"abc\",\"y\":\"def\"}";

    @Mock private PrfSaltUseCase prfSaltUseCase;
    @Mock private WrappedKeyHandleRepository wrappedKeyHandleRepository;
    @Mock private PreparedSignStore preparedSignStore;

    private PrepareSignUseCase useCase;

    @BeforeEach
    void setUp() {
        useCase = new PrepareSignUseCase(
                prfSaltUseCase, wrappedKeyHandleRepository, preparedSignStore, new ObjectMapper());
    }

    // ------------------------------------------------------------------ happy path

    @Test
    void execute_happyPath_returnsPrepareSignResponse() {
        givenMaterialResolvesSuccessfully();
        when(preparedSignStore.putPending(any(), any())).thenReturn(Mono.empty());

        StepVerifier.create(useCase.execute(request(), "test-corr-id").contextWrite(holderContext()))
                .assertNext(r -> {
                    assertThat(r.prfSalt()).isNotBlank();
                    assertThat(r.wrappedBlob()).isNotBlank();
                    assertThat(r.iv()).isNotBlank();
                    assertThat(r.tag()).isNotBlank();
                    assertThat(r.signingInput()).contains(".");
                    assertThat(r.correlationId()).isNotBlank();
                    assertThat(r.kdfParams()).contains("HKDF-SHA-256");
                })
                .verifyComplete();
    }

    @Test
    void execute_happyPath_prfSaltBase64urlDecodesCorrectly() {
        byte[] salt = new byte[32];
        salt[0] = 0x7F;
        when(prfSaltUseCase.getForHolder(TENANT, HOLDER, CRED_ID)).thenReturn(Mono.just(salt));
        when(wrappedKeyHandleRepository.findBy(HOLDER, CRED_ID))
                .thenReturn(Mono.just(Optional.of(validHandle())));
        when(preparedSignStore.putPending(any(), any())).thenReturn(Mono.empty());

        StepVerifier.create(useCase.execute(request(), "test-corr-id").contextWrite(holderContext()))
                .assertNext(r -> {
                    byte[] decoded = Base64.getUrlDecoder().decode(r.prfSalt());
                    assertThat(decoded).isEqualTo(salt);
                })
                .verifyComplete();
    }

    @Test
    void execute_happyPath_signingInputHasHeaderAndPayload() {
        givenMaterialResolvesSuccessfully();
        when(preparedSignStore.putPending(any(), any())).thenReturn(Mono.empty());

        StepVerifier.create(useCase.execute(request(), "test-corr-id").contextWrite(holderContext()))
                .assertNext(r -> {
                    String[] parts = r.signingInput().split("\\.");
                    assertThat(parts).hasSize(2);
                    // Both parts must be non-empty base64url
                    assertThat(parts[0]).isNotBlank();
                    assertThat(parts[1]).isNotBlank();
                })
                .verifyComplete();
    }

    @Test
    void execute_happyPath_storesPendingSession() {
        givenMaterialResolvesSuccessfully();
        when(preparedSignStore.putPending(any(), any())).thenReturn(Mono.empty());

        StepVerifier.create(useCase.execute(request(), "test-corr-id").contextWrite(holderContext()))
                .assertNext(r -> verify(preparedSignStore).putPending(eq(r.correlationId()), any()))
                .verifyComplete();
    }

    @Test
    void execute_happyPath_correlationIdIsEchoedFromInput() {
        givenMaterialResolvesSuccessfully();
        when(preparedSignStore.putPending(any(), any())).thenReturn(Mono.empty());

        String inputCorrelationId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
        StepVerifier.create(useCase.execute(request(), inputCorrelationId).contextWrite(holderContext()))
                .assertNext(r -> assertThat(r.correlationId()).isEqualTo(inputCorrelationId))
                .verifyComplete();
    }

    // ------------------------------------------------------------------ handle not found

    @Test
    void execute_wrappedHandleNotFound_throwsPrfSaltNotFoundException() {
        when(prfSaltUseCase.getForHolder(TENANT, HOLDER, CRED_ID)).thenReturn(Mono.just(PRF_SALT));
        when(wrappedKeyHandleRepository.findBy(HOLDER, CRED_ID))
                .thenReturn(Mono.just(Optional.empty()));

        StepVerifier.create(useCase.execute(request(), "test-corr-id").contextWrite(holderContext()))
                .expectError(PrfSaltNotFoundException.class)
                .verify();

        verify(preparedSignStore, never()).putPending(any(), any());
    }

    // ------------------------------------------------------------------ holder isolation

    @Test
    void execute_holderIsolationViolation_propagatesException() {
        when(prfSaltUseCase.getForHolder(TENANT, HOLDER, CRED_ID))
                .thenReturn(Mono.error(new HolderIsolationViolationException(CRED_ID)));
        when(wrappedKeyHandleRepository.findBy(HOLDER, CRED_ID))
                .thenReturn(Mono.just(Optional.of(validHandle())));

        StepVerifier.create(useCase.execute(request(), "test-corr-id").contextWrite(holderContext()))
                .expectError(HolderIsolationViolationException.class)
                .verify();

        verify(preparedSignStore, never()).putPending(any(), any());
    }

    // ------------------------------------------------------------------ DB failure

    @Test
    void execute_dbFailure_propagatesReactively() {
        when(prfSaltUseCase.getForHolder(TENANT, HOLDER, CRED_ID))
                .thenReturn(Mono.error(new RuntimeException("R2DBC timeout")));
        when(wrappedKeyHandleRepository.findBy(HOLDER, CRED_ID))
                .thenReturn(Mono.just(Optional.of(validHandle())));

        StepVerifier.create(useCase.execute(request(), "test-corr-id").contextWrite(holderContext()))
                .expectError(RuntimeException.class)
                .verify();
    }

    // ------------------------------------------------------------------ helpers

    private PrepareSignRequest request() {
        return new PrepareSignRequest(CRED_ID, CHALLENGE, FORMAT);
    }

    private reactor.util.context.Context holderContext() {
        return reactor.util.context.Context.of(
                ReactorContextKeys.HOLDER_ID, HOLDER,
                ReactorContextKeys.TENANT_DOMAIN, TENANT);
    }

    private void givenMaterialResolvesSuccessfully() {
        when(prfSaltUseCase.getForHolder(TENANT, HOLDER, CRED_ID)).thenReturn(Mono.just(PRF_SALT));
        when(wrappedKeyHandleRepository.findBy(HOLDER, CRED_ID))
                .thenReturn(Mono.just(Optional.of(validHandle())));
    }

    private WrappedKeyHandle validHandle() {
        return new WrappedKeyHandle(
                HOLDER, CRED_ID, BLOB_BYTES, IV_BYTES, TAG_BYTES,
                "HKDF-SHA-256", 1, CNF_JWK, Instant.now(), null);
    }
}
