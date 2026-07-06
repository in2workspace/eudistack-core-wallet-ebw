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

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
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
    private static final String FORMAT  = "vc+sd-jwt";
    private static final Map<String, Object> PAYLOAD = new LinkedHashMap<>(Map.of(
            "nonce", "test-vp-challenge-abc",
            "iat", 1_700_000_000,
            "aud", "https://verifier.example",
            "sd_hash", "test-sd-hash-value"));

    private static final byte[] PRF_SALT    = new byte[32];
    private static final byte[] BLOB_BYTES  = new byte[48];
    private static final byte[] IV_BYTES    = new byte[12];
    private static final byte[] TAG_BYTES   = new byte[16];
    // RFC 7515 Appendix A.3 example ES256 public key — genuinely valid P-256 coordinates,
    // required by buildVpEnvelopeHeader's JWK.parse(...).toPublicJWK() (VC_JWT format).
    private static final String CNF_JWK = "{\"kty\":\"EC\",\"crv\":\"P-256\","
            + "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\","
            + "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}";

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

                    String header = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
                    assertThat(header).contains("\"typ\":\"kb+jwt\"");
                })
                .verifyComplete();
    }

    /**
     * Design correction (2026-07-03, architecture.md §6.2): signing_input's payload MUST be
     * exactly the client-assembled payload (aud, sd_hash included) — the EBW must NOT
     * reconstruct it from a challenge string alone. A KB-JWT missing sd_hash/aud is invalid
     * per RFC 9901 §4.1.2.
     */
    @Test
    void execute_happyPath_signingInputPayloadIsClientAssembledOpaquePayload() {
        givenMaterialResolvesSuccessfully();
        when(preparedSignStore.putPending(any(), any())).thenReturn(Mono.empty());

        StepVerifier.create(useCase.execute(request(), "test-corr-id").contextWrite(holderContext()))
                .assertNext(r -> {
                    String[] parts = r.signingInput().split("\\.");
                    String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);

                    assertThat(payloadJson).contains("\"nonce\":\"test-vp-challenge-abc\"");
                    assertThat(payloadJson).contains("\"aud\":\"https://verifier.example\"");
                    assertThat(payloadJson).contains("\"sd_hash\":\"test-sd-hash-value\"");
                    assertThat(payloadJson).contains("\"iat\":1700000000");
                })
                .verifyComplete();
    }

    @Test
    void execute_vcJwtFormat_buildsVpEnvelopeHeaderWithJwk() {
        when(prfSaltUseCase.getForHolder(TENANT, HOLDER, CRED_ID)).thenReturn(Mono.just(PRF_SALT));
        when(wrappedKeyHandleRepository.findBy(HOLDER, CRED_ID))
                .thenReturn(Mono.just(Optional.of(validHandle())));
        when(preparedSignStore.putPending(any(), any())).thenReturn(Mono.empty());

        StepVerifier.create(useCase.execute(requestWithFormat("jwt_vc_json"), "test-corr-id")
                        .contextWrite(holderContext()))
                .assertNext(r -> {
                    String header = new String(
                            Base64.getUrlDecoder().decode(r.signingInput().split("\\.")[0]), StandardCharsets.UTF_8);
                    assertThat(header).contains("\"typ\":\"vp+jwt\"");
                    assertThat(header).contains("\"cty\":\"vp\"");
                    assertThat(header).contains("\"jwk\"");
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

    // ------------------------------------------------------------------ malformed stored cnf.jwk (W2, code review 2026-07-06)

    /**
     * {@code buildVpEnvelopeHeader} is new logic introduced by this fix (parses the stored
     * {@code cnf.jwk} for VC_JWT format). A corrupted/malformed value must fail loudly
     * ({@link IllegalStateException}, mapped to a generic 500 by
     * {@code HybridKeyManagerExceptionHandler#handleGeneral} — class name only, no detail
     * leaked) rather than silently produce an invalid header.
     */
    @Test
    void execute_vcJwtFormatWithMalformedCnfJwk_propagatesIllegalStateException() {
        when(prfSaltUseCase.getForHolder(TENANT, HOLDER, CRED_ID)).thenReturn(Mono.just(PRF_SALT));
        when(wrappedKeyHandleRepository.findBy(HOLDER, CRED_ID))
                .thenReturn(Mono.just(Optional.of(handleWithCnfJwk("not-a-valid-jwk"))));

        StepVerifier.create(useCase.execute(requestWithFormat("jwt_vc_json"), "test-corr-id")
                        .contextWrite(holderContext()))
                .expectError(IllegalStateException.class)
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
        return new PrepareSignRequest(CRED_ID, PAYLOAD, FORMAT);
    }

    private PrepareSignRequest requestWithFormat(String format) {
        return new PrepareSignRequest(CRED_ID, PAYLOAD, format);
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
        return handleWithCnfJwk(CNF_JWK);
    }

    private WrappedKeyHandle handleWithCnfJwk(String cnfJwk) {
        return new WrappedKeyHandle(
                HOLDER, CRED_ID, BLOB_BYTES, IV_BYTES, TAG_BYTES,
                "HKDF-SHA-256", 1, cnfJwk, Instant.now(), null);
    }
}
