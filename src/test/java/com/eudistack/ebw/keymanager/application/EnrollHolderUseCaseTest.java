package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.exception.InvalidCommitException;
import com.eudistack.ebw.keymanager.domain.exception.OnboardingStateException;
import com.eudistack.ebw.keymanager.domain.model.EnrollHolderCommitRequest;
import com.eudistack.ebw.keymanager.domain.model.EnrollHolderCommitResponse;
import com.eudistack.ebw.keymanager.domain.model.EnrollHolderInitRequest;
import com.eudistack.ebw.keymanager.domain.model.EnrollHolderInitResponse;
import com.eudistack.ebw.keymanager.domain.model.WrappedKeyHandle;
import com.eudistack.ebw.keymanager.domain.port.WrappedKeyHandleRepository;
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
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link EnrollHolderUseCase}.
 *
 * <p>Tests cover the commit path (happy path, idempotent replay, conflict, validation
 * errors) and the init delegation path. The PRF salt generation logic itself is tested
 * in US-05 ({@code PrfSaltUseCaseTest}).</p>
 *
 * <p>Spec: EUDISTACK-534 AC-02..AC-07, ES-01..ES-03.</p>
 */
@ExtendWith(MockitoExtension.class)
class EnrollHolderUseCaseTest {

    private static final String TENANT    = "sandbox";
    private static final String HOLDER    = "holder-uuid-1";
    private static final String CRED_ID   = "cred-id-1";

    // Minimal valid binary fixtures (zero bytes, valid lengths)
    private static final byte[] BLOB_BYTES = new byte[48];
    private static final byte[] IV_BYTES   = new byte[12];
    private static final byte[] TAG_BYTES  = new byte[16];

    private static final String BLOB_B64 = Base64.getUrlEncoder().withoutPadding().encodeToString(BLOB_BYTES);
    private static final String IV_B64   = Base64.getUrlEncoder().withoutPadding().encodeToString(IV_BYTES);
    private static final String TAG_B64  = Base64.getUrlEncoder().withoutPadding().encodeToString(TAG_BYTES);
    private static final String CNF_JWK  = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"abc\",\"y\":\"def\"}";

    @Mock private PrfSaltUseCase prfSaltUseCase;
    @Mock private WrappedKeyHandleRepository repository;

    private EnrollHolderUseCase useCase;

    @BeforeEach
    void setUp() {
        useCase = new EnrollHolderUseCase(prfSaltUseCase, repository);
    }

    // ------------------------------------------------------------------ init

    @Test
    void init_delegatesToPrfSaltUseCase_andReturnsSalt() {
        byte[] salt = new byte[32];
        salt[0] = 0x01;
        when(prfSaltUseCase.getOrCreatePrfSalt(TENANT, HOLDER, CRED_ID)).thenReturn(Mono.just(salt));

        StepVerifier.create(useCase.init(TENANT, HOLDER, new EnrollHolderInitRequest(CRED_ID, "vc+sd-jwt")))
                .assertNext(response -> {
                    assertThat(response.prfSalt()).isNotBlank();
                    assertThat(response.kdfParams()).contains("HKDF-SHA-256");
                    assertThat(response.kdfParams()).contains("hybrid-wrap-v1");
                    assertThat(response.signingPubkeyEnvelopeFormat()).isEqualTo("SD-JWT");
                })
                .verifyComplete();
    }

    @Test
    void init_prfSaltBase64url_decodesBackToOriginalBytes() {
        byte[] salt = new byte[32];
        for (int i = 0; i < salt.length; i++) salt[i] = (byte) i;
        when(prfSaltUseCase.getOrCreatePrfSalt(TENANT, HOLDER, CRED_ID)).thenReturn(Mono.just(salt));

        StepVerifier.create(useCase.init(TENANT, HOLDER, new EnrollHolderInitRequest(CRED_ID, "vc+sd-jwt")))
                .assertNext(response -> {
                    byte[] decoded = Base64.getUrlDecoder().decode(response.prfSalt());
                    assertThat(decoded).isEqualTo(salt);
                })
                .verifyComplete();
    }

    // --------------------------------------------------------------- commit: happy path

    @Test
    void commit_newHandle_returns201WithCredentialId() {
        when(repository.findBy(HOLDER, CRED_ID)).thenReturn(Mono.just(Optional.empty()));
        when(repository.insert(any())).thenReturn(Mono.empty());

        StepVerifier.create(useCase.commit(HOLDER, validCommitRequest()))
                .assertNext(response -> assertThat(response.credentialId()).isEqualTo(CRED_ID))
                .verifyComplete();

        verify(repository).insert(argThat(handle ->
                handle.holderId().equals(HOLDER)
                && handle.credentialId().equals(CRED_ID)));
    }

    @Test
    void commit_newHandle_persistsKdfMetadata() {
        when(repository.findBy(HOLDER, CRED_ID)).thenReturn(Mono.just(Optional.empty()));
        when(repository.insert(any())).thenReturn(Mono.empty());

        StepVerifier.create(useCase.commit(HOLDER, validCommitRequest()))
                .assertNext(r -> assertThat(r.credentialId()).isEqualTo(CRED_ID))
                .verifyComplete();

        verify(repository).insert(argThat(handle ->
                handle.kdfAlgo().equals("HKDF-SHA-256")
                && handle.kdfVersion() == 1
                && handle.cnfJwk().equals(CNF_JWK)));
    }

    // --------------------------------------------------------------- commit: idempotency

    @Test
    void commit_identicalReplay_acknowledgesWithoutInserting() {
        WrappedKeyHandle existing = existingHandle(BLOB_BYTES, IV_BYTES, TAG_BYTES);
        when(repository.findBy(HOLDER, CRED_ID)).thenReturn(Mono.just(Optional.of(existing)));

        StepVerifier.create(useCase.commit(HOLDER, validCommitRequest()))
                .assertNext(response -> assertThat(response.credentialId()).isEqualTo(CRED_ID))
                .verifyComplete();

        verify(repository, never()).insert(any());
    }

    @Test
    void commit_differentBlob_throwsOnboardingStateException() {
        byte[] differentBlob = new byte[48];
        differentBlob[0] = 0x42;
        WrappedKeyHandle existing = existingHandle(differentBlob, IV_BYTES, TAG_BYTES);
        when(repository.findBy(HOLDER, CRED_ID)).thenReturn(Mono.just(Optional.of(existing)));

        StepVerifier.create(useCase.commit(HOLDER, validCommitRequest()))
                .expectError(OnboardingStateException.class)
                .verify();

        verify(repository, never()).insert(any());
    }

    // --------------------------------------------------------------- commit: validation

    @Test
    void commit_wrappedBlobTooShort_throwsInvalidCommitException() {
        byte[] shortBlob = new byte[47];
        String shortBlobB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(shortBlob);

        StepVerifier.create(useCase.commit(HOLDER,
                new EnrollHolderCommitRequest(CRED_ID, shortBlobB64, IV_B64, TAG_B64,
                        "HKDF-SHA-256", 1, CNF_JWK)))
                .expectError(InvalidCommitException.class)
                .verify();

        verify(repository, never()).findBy(any(), any());
    }

    @Test
    void commit_ivWrongLength_throwsInvalidCommitException() {
        byte[] wrongIv = new byte[11];
        String wrongIvB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(wrongIv);

        StepVerifier.create(useCase.commit(HOLDER,
                new EnrollHolderCommitRequest(CRED_ID, BLOB_B64, wrongIvB64, TAG_B64,
                        "HKDF-SHA-256", 1, CNF_JWK)))
                .expectError(InvalidCommitException.class)
                .verify();
    }

    @Test
    void commit_tagWrongLength_throwsInvalidCommitException() {
        byte[] wrongTag = new byte[15];
        String wrongTagB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(wrongTag);

        StepVerifier.create(useCase.commit(HOLDER,
                new EnrollHolderCommitRequest(CRED_ID, BLOB_B64, IV_B64, wrongTagB64,
                        "HKDF-SHA-256", 1, CNF_JWK)))
                .expectError(InvalidCommitException.class)
                .verify();
    }

    // AC-03 (cnf_jwk must not contain "d") is validated by HybridOnboardingController before
    // reaching this use case — see EnrollHolderControllerIT for coverage.

    @Test
    void commit_invalidBase64url_throwsInvalidCommitException() {
        StepVerifier.create(useCase.commit(HOLDER,
                new EnrollHolderCommitRequest(CRED_ID, "not-valid-base64!!!", IV_B64, TAG_B64,
                        "HKDF-SHA-256", 1, CNF_JWK)))
                .expectError(InvalidCommitException.class)
                .verify();
    }

    // --------------------------------------------------------------- helpers

    private EnrollHolderCommitRequest validCommitRequest() {
        return new EnrollHolderCommitRequest(CRED_ID, BLOB_B64, IV_B64, TAG_B64,
                "HKDF-SHA-256", 1, CNF_JWK);
    }

    private WrappedKeyHandle existingHandle(byte[] blob, byte[] iv, byte[] tag) {
        return new WrappedKeyHandle(
                HOLDER, CRED_ID,
                blob, iv, tag,
                "HKDF-SHA-256", 1,
                CNF_JWK,
                Instant.now(), null);
    }
}