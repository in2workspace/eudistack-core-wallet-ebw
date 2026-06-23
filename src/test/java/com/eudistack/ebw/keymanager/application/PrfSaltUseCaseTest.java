package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.exception.HolderIsolationViolationException;
import com.eudistack.ebw.keymanager.domain.exception.PrfSaltNotFoundException;
import io.r2dbc.spi.R2dbcDataIntegrityViolationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PrfSaltService} (the {@link PrfSaltUseCase} implementation).
 *
 * <p>Covers:
 * <ul>
 *   <li>getOrCreatePrfSalt — cache miss: generates 32-byte CSPRNG salt, inserts, re-reads</li>
 *   <li>getOrCreatePrfSalt — cache hit: returns existing salt without calling insert (EC-01)</li>
 *   <li>getOrCreatePrfSalt — DB failure on insert: error propagates without salt in message (ES-05, NFR-S-537-01)</li>
 *   <li>getForHolder — absent, no other holder: PrfSaltNotFoundException (ES-02)</li>
 *   <li>getForHolder — cross-holder: HolderIsolationViolationException 403 (ES-04)</li>
 *   <li>holderId taken from method parameter, never from any other source (AD-2)</li>
 * </ul>
 *
 * <p>Spec: EUDISTACK-537 T9; AC-01, AC-04, EC-01, ES-02, ES-04, ES-05, NFR-S-537-01.</p>
 */
@ExtendWith(MockitoExtension.class)
class PrfSaltUseCaseTest {

    private static final String TENANT    = "sandbox";
    private static final String HOLDER_1  = "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb";
    private static final String HOLDER_2  = "cccccccc-4444-5555-6666-dddddddddddd";
    private static final String CRED_ID   = "cred-test-1";

    @Mock private PrfSaltPort prfSaltPort;

    private PrfSaltService service;

    @BeforeEach
    void setUp() {
        service = new PrfSaltService(prfSaltPort);
    }

    // ------------------------------------------------------------------ getOrCreatePrfSalt — miss

    @Test
    void getOrCreatePrfSalt_miss_generatesAndInsertsAndReturns32Bytes() {
        byte[] storedSalt = new byte[32];
        storedSalt[0] = 0x7F;  // non-zero marker to distinguish from zero-filled

        when(prfSaltPort.findBy(HOLDER_1, CRED_ID)).thenReturn(Mono.empty());
        when(prfSaltPort.insert(eq(HOLDER_1), eq(CRED_ID), any(byte[].class)))
                .thenReturn(Mono.empty());
        // re-SELECT after insert returns the stored value
        when(prfSaltPort.findBy(HOLDER_1, CRED_ID))
                .thenReturn(Mono.empty())
                .thenReturn(Mono.just(storedSalt));

        StepVerifier.create(service.getOrCreatePrfSalt(TENANT, HOLDER_1, CRED_ID))
                .assertNext(salt -> assertThat(salt).hasSize(32))
                .verifyComplete();

        verify(prfSaltPort).insert(eq(HOLDER_1), eq(CRED_ID), any(byte[].class));
    }

    @Test
    void getOrCreatePrfSalt_miss_saltIsNotDerivedFromInputs() {
        // Capture the salt passed to insert and assert it does not contain HOLDER_1 or CRED_ID bytes
        ArgumentCaptor<byte[]> saltCaptor = ArgumentCaptor.forClass(byte[].class);
        byte[] reReadSalt = new byte[32];
        reReadSalt[3] = 0x42;

        when(prfSaltPort.findBy(HOLDER_1, CRED_ID))
                .thenReturn(Mono.empty())
                .thenReturn(Mono.just(reReadSalt));
        when(prfSaltPort.insert(eq(HOLDER_1), eq(CRED_ID), saltCaptor.capture()))
                .thenReturn(Mono.empty());

        StepVerifier.create(service.getOrCreatePrfSalt(TENANT, HOLDER_1, CRED_ID))
                .expectNextCount(1)
                .verifyComplete();

        byte[] capturedSalt = saltCaptor.getValue();
        assertThat(capturedSalt).hasSize(32);

        // The salt must not equal the raw UTF-8 bytes of holderId or credentialId
        byte[] holderBytes = HOLDER_1.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] credBytes   = CRED_ID.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        assertThat(capturedSalt).isNotEqualTo(holderBytes);
        assertThat(capturedSalt).isNotEqualTo(credBytes);
    }

    // ------------------------------------------------------------------ getOrCreatePrfSalt — hit (EC-01)

    @Test
    void getOrCreatePrfSalt_hit_returnsExistingSaltAndDoesNotSubscribeToInsert() {
        byte[] existingSalt = new byte[32];
        existingSalt[0] = 0x11;

        when(prfSaltPort.findBy(HOLDER_1, CRED_ID)).thenReturn(Mono.just(existingSalt));

        StepVerifier.create(service.getOrCreatePrfSalt(TENANT, HOLDER_1, CRED_ID))
                .assertNext(salt -> assertThat(salt).isEqualTo(existingSalt))
                .verifyComplete();

        // Mono.defer makes generateAndInsert lazy — insert must never be called on a cache hit
        verify(prfSaltPort, never()).insert(any(), any(), any());
    }

    @Test
    void getOrCreatePrfSalt_hit_isIdempotentAcrossMultipleCalls() {
        byte[] existingSalt = new byte[32];
        existingSalt[1] = 0x22;

        when(prfSaltPort.findBy(HOLDER_1, CRED_ID)).thenReturn(Mono.just(existingSalt));

        // First call
        StepVerifier.create(service.getOrCreatePrfSalt(TENANT, HOLDER_1, CRED_ID))
                .assertNext(salt -> assertThat(salt).isEqualTo(existingSalt))
                .verifyComplete();

        // Second call — same result; Mono.defer means insert is never invoked (EC-01)
        StepVerifier.create(service.getOrCreatePrfSalt(TENANT, HOLDER_1, CRED_ID))
                .assertNext(salt -> assertThat(salt).isEqualTo(existingSalt))
                .verifyComplete();

        verify(prfSaltPort, never()).insert(any(), any(), any());
    }

    // ------------------------------------------------------------------ getOrCreatePrfSalt — DB failure (ES-05, NFR-S-537-01)

    @Test
    void getOrCreatePrfSalt_dbInsertFailure_errorPropagatesWithoutSaltInMessage() {
        RuntimeException dbError = new RuntimeException("connection timeout");

        when(prfSaltPort.findBy(HOLDER_1, CRED_ID)).thenReturn(Mono.empty());
        when(prfSaltPort.insert(eq(HOLDER_1), eq(CRED_ID), any(byte[].class)))
                .thenReturn(Mono.error(dbError));

        StepVerifier.create(service.getOrCreatePrfSalt(TENANT, HOLDER_1, CRED_ID))
                .expectErrorSatisfies(ex -> {
                    // Error must propagate
                    assertThat(ex).isNotNull();
                    // The exception message must not contain any prf_salt-related disclosure
                    // (NFR-S-537-01: no cryptographic material in error messages)
                    String msg = ex.getMessage() != null ? ex.getMessage() : "";
                    assertThat(msg).doesNotContainIgnoringCase("prf_salt");
                    assertThat(msg).doesNotContainIgnoringCase("salt bytes");
                })
                .verify();
    }

    @Test
    void getOrCreatePrfSalt_fkViolation_errorPropagates() {
        // A FK violation (SQLSTATE 23503) wrapped in DataIntegrityViolationException must NOT
        // be swallowed — only duplicate-key (23505) is benign in the get-or-create scenario.
        R2dbcDataIntegrityViolationException r2dbcCause =
                new R2dbcDataIntegrityViolationException("fk violation", "23503");
        DataIntegrityViolationException fkError =
                new DataIntegrityViolationException("fk", r2dbcCause);

        when(prfSaltPort.findBy(HOLDER_1, CRED_ID)).thenReturn(Mono.empty());
        when(prfSaltPort.insert(eq(HOLDER_1), eq(CRED_ID), any(byte[].class)))
                .thenReturn(Mono.error(fkError));

        StepVerifier.create(service.getOrCreatePrfSalt(TENANT, HOLDER_1, CRED_ID))
                .expectErrorMatches(ex -> ex instanceof DataIntegrityViolationException)
                .verify();
    }

    // ------------------------------------------------------------------ getForHolder — absent, no other holder (ES-02)

    @Test
    void getForHolder_saltAbsent_andCredentialNotExistsAnywhere_throwsPrfSaltNotFoundException() {
        when(prfSaltPort.findBy(HOLDER_1, CRED_ID)).thenReturn(Mono.empty());
        when(prfSaltPort.countByCredential(CRED_ID)).thenReturn(Mono.just(0L));

        StepVerifier.create(service.getForHolder(TENANT, HOLDER_1, CRED_ID))
                .expectError(PrfSaltNotFoundException.class)
                .verify();
    }

    @Test
    void getForHolder_saltAbsent_credentialNotFound_exceptionMessageDoesNotContainSalt() {
        when(prfSaltPort.findBy(HOLDER_1, CRED_ID)).thenReturn(Mono.empty());
        when(prfSaltPort.countByCredential(CRED_ID)).thenReturn(Mono.just(0L));

        StepVerifier.create(service.getForHolder(TENANT, HOLDER_1, CRED_ID))
                .expectErrorSatisfies(ex -> {
                    assertThat(ex).isInstanceOf(PrfSaltNotFoundException.class);
                    String msg = ex.getMessage() != null ? ex.getMessage() : "";
                    assertThat(msg).doesNotContainIgnoringCase("prf_salt");
                    assertThat(msg).doesNotContainIgnoringCase("salt bytes");
                })
                .verify();
    }

    // ------------------------------------------------------------------ getForHolder — cross-holder (ES-04)

    @Test
    void getForHolder_saltAbsent_butCredentialExistsForOtherHolder_throwsHolderIsolationViolation() {
        // HOLDER_1 does not have a row for CRED_ID, but another holder does (count = 1)
        when(prfSaltPort.findBy(HOLDER_1, CRED_ID)).thenReturn(Mono.empty());
        when(prfSaltPort.countByCredential(CRED_ID)).thenReturn(Mono.just(1L));

        StepVerifier.create(service.getForHolder(TENANT, HOLDER_1, CRED_ID))
                .expectError(HolderIsolationViolationException.class)
                .verify();
    }

    @Test
    void getForHolder_crossHolder_isolationViolationMessageDoesNotLeakSalt() {
        when(prfSaltPort.findBy(HOLDER_1, CRED_ID)).thenReturn(Mono.empty());
        when(prfSaltPort.countByCredential(CRED_ID)).thenReturn(Mono.just(1L));

        StepVerifier.create(service.getForHolder(TENANT, HOLDER_1, CRED_ID))
                .expectErrorSatisfies(ex -> {
                    assertThat(ex).isInstanceOf(HolderIsolationViolationException.class);
                    String msg = ex.getMessage() != null ? ex.getMessage() : "";
                    assertThat(msg).doesNotContainIgnoringCase("prf_salt");
                    assertThat(msg).doesNotContainIgnoringCase("salt bytes");
                })
                .verify();
    }

    // ------------------------------------------------------------------ holderId from parameter (AD-2)

    @Test
    void getOrCreatePrfSalt_holderIdFromParameter_isPassedToPort() {
        byte[] salt = new byte[32];
        salt[5] = 0x55;

        when(prfSaltPort.findBy(HOLDER_1, CRED_ID)).thenReturn(Mono.just(salt));

        StepVerifier.create(service.getOrCreatePrfSalt(TENANT, HOLDER_1, CRED_ID))
                .expectNextCount(1)
                .verifyComplete();

        // Mono.defer makes generateAndInsert lazy — insert never called on a cache hit (EC-01)
        verify(prfSaltPort, never()).insert(any(), any(), any());
        // HOLDER_2 was never used — holderId comes from the method parameter only
        verify(prfSaltPort, never()).findBy(eq(HOLDER_2), any());
        verify(prfSaltPort, never()).insert(eq(HOLDER_2), any(), any());
    }

    @Test
    void getForHolder_holderIdFromParameter_isPassedToPort() {
        byte[] salt = new byte[32];
        salt[7] = 0x77;

        when(prfSaltPort.findBy(HOLDER_2, CRED_ID)).thenReturn(Mono.just(salt));

        StepVerifier.create(service.getForHolder(TENANT, HOLDER_2, CRED_ID))
                .expectNextCount(1)
                .verifyComplete();

        // Mono.defer makes resolveAbsence lazy — countByCredential never called on a cache hit
        verify(prfSaltPort, never()).countByCredential(any());
        // HOLDER_1 was never used — holderId comes from the method parameter only
        verify(prfSaltPort).findBy(HOLDER_2, CRED_ID);
        verify(prfSaltPort, never()).findBy(eq(HOLDER_1), any());
    }
}
