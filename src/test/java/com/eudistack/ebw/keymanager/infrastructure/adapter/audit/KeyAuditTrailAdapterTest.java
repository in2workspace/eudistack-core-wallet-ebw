package com.eudistack.ebw.keymanager.infrastructure.adapter.audit;

import com.eudistack.ebw.domain.model.audit.AuditEntry;
import com.eudistack.ebw.domain.model.audit.AuditEventType;
import com.eudistack.ebw.domain.model.audit.AuditResult;
import com.eudistack.ebw.infrastructure.adapter.audit.RecordingAuditTrail;
import com.eudistack.ebw.keymanager.domain.model.ConsumerOrigin;
import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent.KeyAuditEventType;
import com.eudistack.ebw.keymanager.domain.model.SignaturePurpose;
import com.eudistack.ebw.keymanager.domain.model.SigningType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import reactor.test.StepVerifier;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class KeyAuditTrailAdapterTest {

    private static final String TENANT = "sandbox";
    private static final String HOLDER = "0b6f1d2e-0000-4000-8000-000000000001";
    private static final String CREDENTIAL = "cred-1";
    private static final Instant NOW = Instant.parse("2026-11-05T10:00:00Z");

    private final RecordingAuditTrail trail = new RecordingAuditTrail();
    private final KeyAuditTrailAdapter adapter = new KeyAuditTrailAdapter(trail);

    @Test
    void generation_isASuccessfulGenerateOperationOfTheServerCustody() {
        emit(KeyAuditEvent.forGeneration(KeyAuditEventType.KEY_GENERATED, TENANT, HOLDER, CREDENTIAL,
                CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256, "jkt-1", NOW, "corr"));

        AuditEntry entry = onlyEntry();
        assertThat(entry.type()).isEqualTo(AuditEventType.HOLDER_KEY_OPERATION);
        assertThat(entry.resource()).isEqualTo("holder-key:" + CREDENTIAL);
        assertThat(entry.result()).isEqualTo(AuditResult.SUCCESS);
        assertThat(entry.reason()).isNull();
        assertThat(entry.details())
                .containsEntry("operation", "Generate")
                .containsEntry("custody_mode", "server")
                .containsEntry("holder_id", HOLDER)
                .containsEntry("jkt", "jkt-1")
                .containsEntry("algorithm", "ES256");
    }

    @Test
    void signature_carriesTheSigningContext() {
        emit(KeyAuditEvent.forSigning(KeyAuditEventType.KEY_SIGNED, TENANT, HOLDER, CREDENTIAL,
                CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256, "jkt-1", NOW, "corr",
                SigningType.KB_JWT, SignaturePurpose.PRESENTATION, ConsumerOrigin.OID4VP_RESPONDER, null, "key-1"));

        assertThat(onlyEntry().details())
                .containsEntry("operation", "Sign")
                .containsEntry("key_id", "key-1")
                .containsEntry("signing_type", "KB_JWT")
                .containsEntry("purpose", "PRESENTATION")
                .containsEntry("consumer_origin", "OID4VP_RESPONDER");
    }

    @Test
    void keyDeletion_isASuccessfulDeleteWithoutKeyContext() {
        emit(KeyAuditEvent.forKeyDeleted(TENANT, HOLDER, CREDENTIAL, "key-1", NOW, "corr"));

        AuditEntry entry = onlyEntry();
        assertThat(entry.result()).isEqualTo(AuditResult.SUCCESS);
        assertThat(entry.details())
                .containsEntry("operation", "Delete")
                .containsEntry("custody_mode", "server")
                .containsEntry("key_id", "key-1")
                .doesNotContainKeys("jkt", "algorithm", "signing_type");
    }

    @ParameterizedTest
    @CsvSource({
            "SALT_CREATED,SaltCreate",
            "SALT_DELIVERED,SaltDeliver",
            "SALT_DELETED,SaltDelete"
    })
    void saltOperations_areSuccessfulOperationsOfThePasskeyCustody(KeyAuditEventType type, String operation) {
        emit(KeyAuditEvent.forSalt(type, TENANT, HOLDER, CREDENTIAL, null, NOW, "corr"));

        AuditEntry entry = onlyEntry();
        assertThat(entry.result()).isEqualTo(AuditResult.SUCCESS);
        assertThat(entry.details())
                .containsEntry("operation", operation)
                .containsEntry("custody_mode", "passkey");
    }

    @ParameterizedTest
    @CsvSource({
            "NOT_FOUND,SaltNotFound",
            "OTHER_PASSKEY,SaltOtherPasskey",
            "NO_PUBLIC_KEY,SaltNoPublicKey",
            "SOMETHING_ELSE,Rejected"
    })
    void deniedSaltDelivery_isDeniedWithTheCatalogueReason(String reason, String catalogueReason) {
        emit(KeyAuditEvent.forSalt(KeyAuditEventType.SALT_DELIVERY_DENIED, TENANT, HOLDER, CREDENTIAL,
                reason, NOW, "corr"));

        AuditEntry entry = onlyEntry();
        assertThat(entry.result()).isEqualTo(AuditResult.DENIED);
        assertThat(entry.reason()).isEqualTo(catalogueReason);
        assertThat(entry.details()).containsEntry("operation", "SaltDeliver");
    }

    @ParameterizedTest
    @CsvSource({
            "KEY_NOT_FOUND,KeyNotFound",
            "SIGNING_TYPE_FORMAT_MISMATCH,SigningTypeFormatMismatch",
            "ANY_OTHER,Rejected"
    })
    void rejectedSignature_isDeniedWithTheCatalogueReason(String reason, String catalogueReason) {
        emit(signing(KeyAuditEventType.SIGN_REJECTED, reason));

        AuditEntry entry = onlyEntry();
        assertThat(entry.result()).isEqualTo(AuditResult.DENIED);
        assertThat(entry.reason()).isEqualTo(catalogueReason);
    }

    @Test
    void signatureTimeout_isAFailureAndTheUnresolvedKeyPlaceholdersAreOmitted() {
        emit(KeyAuditEvent.forSigning(KeyAuditEventType.SIGN_TIMEOUT, TENANT, HOLDER, "UNKNOWN",
                CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256, "UNKNOWN", NOW, "corr",
                SigningType.KB_JWT, SignaturePurpose.PRESENTATION, ConsumerOrigin.OID4VP_RESPONDER,
                "TIMEOUT", null));

        AuditEntry entry = onlyEntry();
        assertThat(entry.result()).isEqualTo(AuditResult.FAILURE);
        assertThat(entry.reason()).isEqualTo("Timeout");
        assertThat(entry.details()).doesNotContainKeys("jkt", "credential_id", "key_id");
    }

    @Test
    void dependencyFailure_isAFailure() {
        emit(signing(KeyAuditEventType.SIGN_DEPENDENCY_FAILURE, "R2DBC_UNAVAILABLE"));

        AuditEntry entry = onlyEntry();
        assertThat(entry.result()).isEqualTo(AuditResult.FAILURE);
        assertThat(entry.reason()).isEqualTo("DependencyUnavailable");
    }

    @Test
    void brokenAuditChannel_doesNotFailTheKeyOperation() {
        KeyAuditTrailAdapter failing = new KeyAuditTrailAdapter(new RecordingAuditTrail().failing());

        StepVerifier.create(failing.emit(KeyAuditEvent.forKeyDeleted(TENANT, HOLDER, CREDENTIAL, "key-1", NOW, "corr")))
                .verifyComplete();
    }

    private static KeyAuditEvent signing(KeyAuditEventType type, String reason) {
        return KeyAuditEvent.forSigning(type, TENANT, HOLDER, CREDENTIAL, CredentialFormat.SD_JWT_VC,
                KeyAlgorithm.ES256, "jkt-1", NOW, "corr", SigningType.KB_JWT, SignaturePurpose.PRESENTATION,
                ConsumerOrigin.OID4VP_RESPONDER, reason, "key-1");
    }

    private void emit(KeyAuditEvent event) {
        StepVerifier.create(adapter.emit(event)).verifyComplete();
    }

    private AuditEntry onlyEntry() {
        assertThat(trail.staged()).hasSize(1);
        return trail.staged().getFirst();
    }
}
