package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.exception.KeyAccessDeniedException;
import com.eudistack.ebw.keymanager.domain.exception.SigningTypeFormatMismatchException;
import com.eudistack.ebw.keymanager.domain.exception.TenantWalletProfileUnsupportedException;
import com.eudistack.ebw.keymanager.domain.model.ConsumerOrigin;
import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.HolderKey;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyId;
import com.eudistack.ebw.keymanager.domain.model.JwkPublic;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.model.SignHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.SignHolderKeyResult;
import com.eudistack.ebw.keymanager.domain.model.SignaturePurpose;
import com.eudistack.ebw.keymanager.domain.model.SigningType;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyReadPort;
import com.eudistack.ebw.keymanager.domain.port.KeyAuditPort;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import com.eudistack.ebw.wallet.profile.domain.model.TenantWalletProfile;
import com.eudistack.ebw.wallet.profile.domain.model.WalletMode;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SignHolderKeyUseCase}.
 *
 * <p>Covers: happy path (AC-01, AC-02), format mismatch (AC-04, EC-02), revoked key (EC-01),
 * opaque reject (AC-06), purpose AUDIT_PROBE (EC-05), tenant profile (ES-03), timeout (ES-05),
 * audit event emission (AC-08).</p>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SignHolderKeyUseCaseTest {

    @Mock private HolderKeyReadPort holderKeyReadPort;
    @Mock private KeyAuditPort auditPort;
    @Mock private WalletProfileQueryPort walletProfileQueryPort;

    private HolderKeyFactory factory;
    private SignerSelector signerSelector;
    private SignRejectionUniformDelay rejectionDelay;
    private SignHolderKeyUseCase useCase;

    @BeforeEach
    void setUp() {
        factory = new HolderKeyFactory();
        signerSelector = new SignerSelector(Map.of(
                SigningType.KB_JWT, new KbJwtSigner(),
                SigningType.VP_ENVELOPE, new VpEnvelopeSigner()
        ));
        // Use 1 ms delay for tests (avoid slowing down suite)
        rejectionDelay = new SignRejectionUniformDelay(1L);
        useCase = new SignHolderKeyUseCase(
                holderKeyReadPort, factory, signerSelector, rejectionDelay, auditPort,
                walletProfileQueryPort);

        // Default: audit always succeeds (fire-and-forget)
        when(auditPort.emit(any())).thenReturn(Mono.empty());
    }

    // --- AC-01: KB_JWT happy path ---

    @Test
    void execute_kbJwt_sdJwtVcKey_returnsValidJws() {
        // Given
        GeneratedKeyPair kp = factory.generate(KeyAlgorithm.ES256);
        HolderKey key = buildHolderKey(kp, CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256);
        when(walletProfileQueryPort.queryByCurrentTenant())
                .thenReturn(Mono.just(serverDbProfile()));
        when(holderKeyReadPort.findById("tenant", key.id())).thenReturn(Mono.just(key));

        SignHolderKeyCommand cmd = signCommand(key.id(), SigningType.KB_JWT, SignaturePurpose.PRESENTATION);

        // When / Then
        StepVerifier.create(useCase.execute(cmd))
                .assertNext(result -> {
                    assertThat(result.jwsCompact()).isNotBlank();
                    assertThat(result.jwsCompact().split("\\.")).hasSize(3);
                    assertThat(result.algorithm()).isEqualTo(KeyAlgorithm.ES256);
                    assertThat(result.jkt()).isNotBlank();
                })
                .verifyComplete();
    }

    // --- AC-02: VP_ENVELOPE happy path ---

    @Test
    void execute_vpEnvelope_vcJwtKey_returnsValidJws() {
        // Given
        GeneratedKeyPair kp = factory.generate(KeyAlgorithm.ES256);
        HolderKey key = buildHolderKey(kp, CredentialFormat.VC_JWT, KeyAlgorithm.ES256);
        when(walletProfileQueryPort.queryByCurrentTenant())
                .thenReturn(Mono.just(serverDbProfile()));
        when(holderKeyReadPort.findById("tenant", key.id())).thenReturn(Mono.just(key));

        SignHolderKeyCommand cmd = signCommand(key.id(), SigningType.VP_ENVELOPE, SignaturePurpose.PRESENTATION);

        // When / Then
        StepVerifier.create(useCase.execute(cmd))
                .assertNext(result -> {
                    assertThat(result.jwsCompact()).isNotBlank();
                    assertThat(result.algorithm()).isEqualTo(KeyAlgorithm.ES256);
                })
                .verifyComplete();
    }

    // --- AC-04 / EC-02: format mismatch ---

    @Test
    void execute_kbJwtWithVcJwtKey_throwsSigningTypeFormatMismatchException() {
        // Given: key is VC_JWT but signing type is KB_JWT
        GeneratedKeyPair kp = factory.generate(KeyAlgorithm.ES256);
        HolderKey key = buildHolderKey(kp, CredentialFormat.VC_JWT, KeyAlgorithm.ES256);
        when(walletProfileQueryPort.queryByCurrentTenant())
                .thenReturn(Mono.just(serverDbProfile()));
        when(holderKeyReadPort.findById("tenant", key.id())).thenReturn(Mono.just(key));

        SignHolderKeyCommand cmd = signCommand(key.id(), SigningType.KB_JWT, SignaturePurpose.PRESENTATION);

        // When / Then
        StepVerifier.create(useCase.execute(cmd))
                .expectError(SigningTypeFormatMismatchException.class)
                .verify();
    }

    // --- AC-06 / ES-02: key not found → opaque reject ---

    @Test
    void execute_keyNotFound_throwsKeyAccessDeniedException() {
        // Given
        HolderKeyId missingId = HolderKeyId.generate();
        when(walletProfileQueryPort.queryByCurrentTenant())
                .thenReturn(Mono.just(serverDbProfile()));
        when(holderKeyReadPort.findById("tenant", missingId)).thenReturn(Mono.empty());

        SignHolderKeyCommand cmd = signCommand(missingId, SigningType.KB_JWT, SignaturePurpose.PRESENTATION);

        // When / Then
        StepVerifier.create(useCase.execute(cmd))
                .expectError(KeyAccessDeniedException.class)
                .verify();
    }

    // --- EC-01: revoked key (findById returns empty because of revoked_at filter) ---

    @Test
    void execute_revokedKey_treatedAsNotFound_throwsKeyAccessDeniedException() {
        // The R2DBC query filters WHERE revoked_at IS NULL — the adapter returns empty
        HolderKeyId revokedId = HolderKeyId.generate();
        when(walletProfileQueryPort.queryByCurrentTenant())
                .thenReturn(Mono.just(serverDbProfile()));
        when(holderKeyReadPort.findById("tenant", revokedId)).thenReturn(Mono.empty());

        SignHolderKeyCommand cmd = signCommand(revokedId, SigningType.KB_JWT, SignaturePurpose.PRESENTATION);

        StepVerifier.create(useCase.execute(cmd))
                .expectError(KeyAccessDeniedException.class)
                .verify();
    }

    // --- ES-03: tenant profile unsupported ---

    @Test
    void execute_browserTenantProfile_throwsTenantWalletProfileUnsupportedException() {
        // Given: browser mode (no key manager)
        Instant now = Instant.now();
        TenantWalletProfile browserProfile = new TenantWalletProfile(
                "tenant", WalletMode.BROWSER, null, now, now);
        when(walletProfileQueryPort.queryByCurrentTenant())
                .thenReturn(Mono.just(browserProfile));

        SignHolderKeyCommand cmd = signCommand(HolderKeyId.generate(), SigningType.KB_JWT, SignaturePurpose.PRESENTATION);

        StepVerifier.create(useCase.execute(cmd))
                .expectError(TenantWalletProfileUnsupportedException.class)
                .verify();
    }

    // --- EC-05: AUDIT_PROBE purpose ---

    @Test
    void execute_auditProbePurpose_completesSuccessfully() {
        // Given
        GeneratedKeyPair kp = factory.generate(KeyAlgorithm.EdDSA);
        HolderKey key = buildHolderKey(kp, CredentialFormat.SD_JWT_VC, KeyAlgorithm.EdDSA);
        when(walletProfileQueryPort.queryByCurrentTenant())
                .thenReturn(Mono.just(serverDbProfile()));
        when(holderKeyReadPort.findById("tenant", key.id())).thenReturn(Mono.just(key));

        SignHolderKeyCommand cmd = signCommand(key.id(), SigningType.KB_JWT, SignaturePurpose.AUDIT_PROBE);

        StepVerifier.create(useCase.execute(cmd))
                .assertNext(result -> assertThat(result.jwsCompact()).isNotBlank())
                .verifyComplete();
    }

    // --- AC-08: audit event emitted on success ---

    @Test
    void execute_happyPath_emitsKeySignedAuditEvent() {
        // Given
        GeneratedKeyPair kp = factory.generate(KeyAlgorithm.ES256);
        HolderKey key = buildHolderKey(kp, CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256);
        when(walletProfileQueryPort.queryByCurrentTenant())
                .thenReturn(Mono.just(serverDbProfile()));
        when(holderKeyReadPort.findById("tenant", key.id())).thenReturn(Mono.just(key));

        SignHolderKeyCommand cmd = signCommand(key.id(), SigningType.KB_JWT, SignaturePurpose.PRESENTATION);

        // When
        StepVerifier.create(useCase.execute(cmd))
                .assertNext(result -> assertThat(result).isNotNull())
                .verifyComplete();

        // Then
        ArgumentCaptor<KeyAuditEvent> eventCaptor = ArgumentCaptor.forClass(KeyAuditEvent.class);
        verify(auditPort).emit(eventCaptor.capture());
        KeyAuditEvent emitted = eventCaptor.getValue();
        assertThat(emitted.type()).isEqualTo(KeyAuditEvent.KeyAuditEventType.KEY_SIGNED);
        assertThat(emitted.signingType()).isEqualTo(SigningType.KB_JWT);
        assertThat(emitted.purpose()).isEqualTo(SignaturePurpose.PRESENTATION);
    }

    // --- EC-03: empty signing input is rejected at command level ---

    @Test
    void execute_emptySigningInput_throwsAtCommandConstruction() {
        // SignHolderKeyCommand compact constructor rejects empty byte arrays
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> new SignHolderKeyCommand(
                HolderKeyId.generate(), "tenant", "holder",
                SigningType.KB_JWT, SignaturePurpose.PRESENTATION, ConsumerOrigin.SYSTEM,
                new byte[0]))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // --- AC-09: two sequential signs produce valid but potentially distinct outputs ---

    @Test
    void execute_twoSequentialSigns_bothReturnValidJws() {
        // Given
        GeneratedKeyPair kp = factory.generate(KeyAlgorithm.ES256);
        HolderKey key = buildHolderKey(kp, CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256);
        when(walletProfileQueryPort.queryByCurrentTenant())
                .thenReturn(Mono.just(serverDbProfile()));
        when(holderKeyReadPort.findById("tenant", key.id())).thenReturn(Mono.just(key));

        SignHolderKeyCommand cmd = signCommand(key.id(), SigningType.KB_JWT, SignaturePurpose.PRESENTATION);

        // When
        SignHolderKeyResult result1 = useCase.execute(cmd).block();
        SignHolderKeyResult result2 = useCase.execute(cmd).block();

        // Then — both valid
        assertThat(result1).isNotNull();
        assertThat(result2).isNotNull();
        assertThat(result1.jwsCompact()).isNotBlank();
        assertThat(result2.jwsCompact()).isNotBlank();
    }

    // --- ES-05: timeout ---

    @Test
    void execute_useCaseTimeout_emitsTimeoutException() {
        // Given — holderKeyReadPort never returns
        when(walletProfileQueryPort.queryByCurrentTenant())
                .thenReturn(Mono.just(serverDbProfile()));
        when(holderKeyReadPort.findById(any(), any())).thenReturn(Mono.never());

        SignHolderKeyCommand cmd = signCommand(HolderKeyId.generate(), SigningType.KB_JWT,
                SignaturePurpose.PRESENTATION);

        StepVerifier.withVirtualTime(() -> useCase.execute(cmd))
                .thenAwait(SignHolderKeyUseCase.OUTER_TIMEOUT.plusMillis(100))
                .expectError(java.util.concurrent.TimeoutException.class)
                .verify();
    }

    // --- ES-04: audit failure does not fail the main flow ---

    @Test
    void execute_auditFailure_doesNotFailMainFlow() {
        // Given
        GeneratedKeyPair kp = factory.generate(KeyAlgorithm.ES256);
        HolderKey key = buildHolderKey(kp, CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256);
        when(walletProfileQueryPort.queryByCurrentTenant())
                .thenReturn(Mono.just(serverDbProfile()));
        when(holderKeyReadPort.findById("tenant", key.id())).thenReturn(Mono.just(key));
        // Audit always fails
        when(auditPort.emit(any())).thenReturn(Mono.error(new RuntimeException("audit down")));

        SignHolderKeyCommand cmd = signCommand(key.id(), SigningType.KB_JWT, SignaturePurpose.PRESENTATION);

        // When / Then — should still complete successfully
        StepVerifier.create(useCase.execute(cmd))
                .assertNext(result -> assertThat(result.jwsCompact()).isNotBlank())
                .verifyComplete();
    }

    // --- helpers ---

    private static TenantWalletProfile serverDbProfile() {
        Instant now = Instant.now();
        return new TenantWalletProfile("tenant", WalletMode.SERVER, KeyManager.DB, now, now);
    }

    private static HolderKey buildHolderKey(GeneratedKeyPair kp, CredentialFormat format,
                                              KeyAlgorithm algorithm) {
        return new HolderKey(
                HolderKeyId.generate(),
                "tenant",
                "holder",
                "cred-1",
                format,
                algorithm,
                kp.rawPrivateBytes().clone(),
                kp.publicJwk(),
                Instant.now(),
                null
        );
    }

    private static SignHolderKeyCommand signCommand(HolderKeyId keyId, SigningType type,
                                                     SignaturePurpose purpose) {
        return new SignHolderKeyCommand(
                keyId, "tenant", "holder",
                type, purpose, ConsumerOrigin.SYSTEM,
                "payload bytes".getBytes()
        );
    }
}
