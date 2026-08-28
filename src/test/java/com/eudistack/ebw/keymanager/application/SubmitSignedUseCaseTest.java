package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.keymanager.domain.exception.HolderIsolationViolationException;
import com.eudistack.ebw.keymanager.domain.exception.InvalidSignatureSubmissionException;
import com.eudistack.ebw.keymanager.domain.exception.SignatureInvalidException;
import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEventAssertions;
import com.eudistack.ebw.keymanager.domain.model.SubmitSignedAssertionRequest;
import com.eudistack.ebw.keymanager.domain.port.KeyAuditPort;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.util.context.Context;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SubmitSignedUseCase}.
 *
 * <p>Uses real EC P-256 key pairs (Nimbus) to exercise actual cryptographic verification
 * against {@code cnf.jwk}. The class-level key pair is generated once and reused across
 * tests to keep the suite fast.</p>
 *
 * <p>Tests cover: happy path, holder isolation, unknown/expired correlation_id,
 * invalid signature (wrong key), and idempotent replay.</p>
 *
 * <p>Spec: EUDISTACK-536 AC-02, AC-08, AC-09, EC-03, ES-01, ES-03, ES-04,
 * NFR-S-536-02, NFR-S-536-03.</p>
 */
@ExtendWith(MockitoExtension.class)
class SubmitSignedUseCaseTest {

    private static final String HOLDER   = "holder-uuid-1";
    private static final String TENANT   = "sandbox";
    private static final String CRED_ID  = "cred-id-1";

    /** Signing key for the "holder" (P-256 key pair generated once). */
    private static ECKey holderKey;
    private static String cnfJwk;       // public JWK JSON string stored in PreparedSign.cnfJwk
    private static String signingInput; // headerB64.payloadB64 produced by PrepareSignUseCase
    private static String validSig;     // base64url signature from signing signingInput with holderKey

    @Mock private PreparedSignStore store;
    @Mock private KeyAuditPort auditPort;

    @InjectMocks private SubmitSignedUseCase useCase;

    @BeforeAll
    static void generateKeyAndSignature() throws Exception {
        holderKey = new ECKeyGenerator(Curve.P_256).generate();
        cnfJwk = holderKey.toPublicJWK().toJSONString();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("kb+jwt"))
                .build();
        Payload payload = new Payload("{\"nonce\":\"test-challenge\",\"iat\":1234567890}");
        JWSObject jwsObject = new JWSObject(header, payload);
        jwsObject.sign(new ECDSASigner(holderKey));

        String compact = jwsObject.serialize();
        String[] parts = compact.split("\\.");
        signingInput = parts[0] + "." + parts[1];
        validSig = parts[2];
    }

    @BeforeEach
    void setUp() {
        lenient().when(auditPort.emit(any())).thenReturn(Mono.empty());
    }

    // ------------------------------------------------------------------ happy path

    @Test
    void execute_validSignature_returnsKbJwt() {
        when(store.getIfPresent(CRED_ID)).thenReturn(Mono.just(Optional.of(pendingSession())));
        when(store.markResolved(eq(CRED_ID), any())).thenReturn(Mono.empty());

        StepVerifier.create(useCase.execute(submitRequest(CRED_ID, validSig)).contextWrite(holderCtx()))
                .assertNext(r -> {
                    assertThat(r.kbJwt()).isNotBlank();
                    assertThat(r.kbJwt()).contains(".");
                    // kb_jwt = signingInput + "." + signature
                    assertThat(r.kbJwt()).startsWith(signingInput + ".");
                })
                .verifyComplete();
    }

    @Test
    void execute_validSignature_marksSessionResolved() {
        when(store.getIfPresent(CRED_ID)).thenReturn(Mono.just(Optional.of(pendingSession())));
        when(store.markResolved(eq(CRED_ID), any())).thenReturn(Mono.empty());

        StepVerifier.create(useCase.execute(submitRequest(CRED_ID, validSig)).contextWrite(holderCtx()))
                .assertNext(r -> verify(store).markResolved(CRED_ID, r.kbJwt()))
                .verifyComplete();
    }

    // ------------------------------------------------------------------ idempotent replay

    @Test
    void execute_alreadyResolved_returnsCachedKbJwtWithoutReverification() {
        String cachedKbJwt = "already.resolved.jwt";
        PreparedSign resolved = new PreparedSign(
                signingInput, cnfJwk, HOLDER, TENANT, CRED_ID, CredentialFormat.SD_JWT_VC, cachedKbJwt);
        when(store.getIfPresent(CRED_ID)).thenReturn(Mono.just(Optional.of(resolved)));

        StepVerifier.create(useCase.execute(submitRequest(CRED_ID, validSig)).contextWrite(holderCtx()))
                .assertNext(r -> assertThat(r.kbJwt()).isEqualTo(cachedKbJwt))
                .verifyComplete();

        verify(store, never()).markResolved(any(), any());
        verify(auditPort, never()).emit(any());
    }

    // ------------------------------------------------------------------ unknown / expired correlation_id

    @Test
    void execute_unknownCorrelationId_throwsInvalidSignatureSubmissionException() {
        when(store.getIfPresent("unknown-corr")).thenReturn(Mono.just(Optional.empty()));

        StepVerifier.create(useCase.execute(submitRequest("unknown-corr", validSig)).contextWrite(holderCtx()))
                .expectError(InvalidSignatureSubmissionException.class)
                .verify();

        verify(store, never()).markResolved(any(), any());
    }

    // ------------------------------------------------------------------ holder isolation

    @Test
    void execute_holderIdMismatch_throwsHolderIsolationViolationException() {
        PreparedSign differentHolder = new PreparedSign(
                signingInput, cnfJwk, "other-holder", TENANT, CRED_ID, CredentialFormat.SD_JWT_VC, null);
        when(store.getIfPresent(CRED_ID)).thenReturn(Mono.just(Optional.of(differentHolder)));

        StepVerifier.create(useCase.execute(submitRequest(CRED_ID, validSig)).contextWrite(holderCtx()))
                .expectError(HolderIsolationViolationException.class)
                .verify();

        verify(store, never()).markResolved(any(), any());
    }

    // ------------------------------------------------------------------ invalid signature

    @Test
    void execute_signatureFromDifferentKey_throwsSignatureInvalidException() throws Exception {
        ECKey attackerKey = new ECKeyGenerator(Curve.P_256).generate();
        JWSObject forged = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("kb+jwt")).build(),
                new Payload("{\"nonce\":\"test-challenge\",\"iat\":1234567890}"));
        forged.sign(new ECDSASigner(attackerKey));
        String forgery = forged.serialize().split("\\.")[2];

        when(store.getIfPresent(CRED_ID)).thenReturn(Mono.just(Optional.of(pendingSession())));

        StepVerifier.create(useCase.execute(submitRequest(CRED_ID, forgery)).contextWrite(holderCtx()))
                .expectError(SignatureInvalidException.class)
                .verify();

        verify(store, never()).markResolved(any(), any());
    }

    // ------------------------------------------------------------------ audit (F2 — NIS2 non-repudiation)

    @Test
    void execute_validSignature_emitsUnwrapSignCompletedAuditEventOnce() throws Exception {
        when(store.getIfPresent(CRED_ID)).thenReturn(Mono.just(Optional.of(pendingSession())));
        when(store.markResolved(eq(CRED_ID), any())).thenReturn(Mono.empty());
        when(auditPort.emit(any())).thenReturn(Mono.empty());

        // Act
        StepVerifier.create(useCase.execute(submitRequest(CRED_ID, validSig)).contextWrite(holderCtx()))
                .assertNext(r -> assertThat(r.kbJwt()).isNotBlank())
                .verifyComplete();

        // Assert — capture emitted event and verify all required fields (GAP-3)
        ArgumentCaptor<KeyAuditEvent> captor = ArgumentCaptor.forClass(KeyAuditEvent.class);
        verify(auditPort).emit(captor.capture());
        KeyAuditEvent emitted = captor.getValue();

        assertThat(emitted.type()).isEqualTo(KeyAuditEvent.KeyAuditEventType.UNWRAP_SIGN_COMPLETED);
        assertThat(emitted.tenantId()).isEqualTo(TENANT);
        assertThat(emitted.holderId()).isNotBlank().isEqualTo(HOLDER);
        assertThat(emitted.credentialId()).isNotBlank().isEqualTo(CRED_ID);
        assertThat(emitted.correlationId()).isNotBlank().isEqualTo(CRED_ID);
        assertThat(emitted.timestamp()).isNotNull();
        KeyAuditEventAssertions.assertNoSensitiveData(emitted);
    }

    @Test
    void execute_signatureFromDifferentKey_emitsUnwrapFailedAuditEvent() throws Exception {
        ECKey attackerKey = new ECKeyGenerator(Curve.P_256).generate();
        JWSObject forged = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("kb+jwt")).build(),
                new Payload("{\"nonce\":\"test-challenge\",\"iat\":1234567890}"));
        forged.sign(new ECDSASigner(attackerKey));
        String forgery = forged.serialize().split("\\.")[2];

        when(store.getIfPresent(CRED_ID)).thenReturn(Mono.just(Optional.of(pendingSession())));
        when(auditPort.emit(any())).thenReturn(Mono.empty());

        // Act
        StepVerifier.create(useCase.execute(submitRequest(CRED_ID, forgery)).contextWrite(holderCtx()))
                .expectError(SignatureInvalidException.class)
                .verify();

        // Assert — capture emitted event and verify all required fields (GAP-3)
        ArgumentCaptor<KeyAuditEvent> captor = ArgumentCaptor.forClass(KeyAuditEvent.class);
        verify(auditPort).emit(captor.capture());
        KeyAuditEvent emitted = captor.getValue();

        assertThat(emitted.type()).isEqualTo(KeyAuditEvent.KeyAuditEventType.UNWRAP_FAILED);
        assertThat(emitted.tenantId()).isEqualTo(TENANT);
        assertThat(emitted.holderId()).isNotBlank().isEqualTo(HOLDER);
        assertThat(emitted.credentialId()).isNotBlank().isEqualTo(CRED_ID);
        assertThat(emitted.reason()).isNotNull();
        assertThat(emitted.correlationId()).isNotBlank().isEqualTo(CRED_ID);
        KeyAuditEventAssertions.assertNoSensitiveData(emitted);
    }

    @Test
    @DisplayName("Audit emit failure does not interrupt the main signing flow")
    void execute_auditEmitFails_doesNotPropagateErrorToMainFlow() {
        // Arrange
        when(store.getIfPresent(CRED_ID)).thenReturn(Mono.just(Optional.of(pendingSession())));
        when(store.markResolved(eq(CRED_ID), any())).thenReturn(Mono.empty());
        when(auditPort.emit(any())).thenReturn(Mono.error(new RuntimeException("CloudWatch down")));

        // Act & Assert
        StepVerifier.create(useCase.execute(submitRequest(CRED_ID, validSig)).contextWrite(holderCtx()))
                .expectNextCount(1)
                .verifyComplete();

        // Assert
        verify(auditPort).emit(any());
    }

    // ------------------------------------------------------------------ helpers

    private PreparedSign pendingSession() {
        return new PreparedSign(signingInput, cnfJwk, HOLDER, TENANT, CRED_ID, CredentialFormat.SD_JWT_VC, null);
    }

    private SubmitSignedAssertionRequest submitRequest(String correlationId, String signature) {
        return new SubmitSignedAssertionRequest(CRED_ID, signature, correlationId);
    }

    private Context holderCtx() {
        return Context.of(ReactorContextKeys.HOLDER_ID, HOLDER);
    }
}
