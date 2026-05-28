package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.exception.UnsupportedJwsAlgorithmException;
import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.GenerateHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.HolderKey;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyPersistResult;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyWritePort;
import com.eudistack.ebw.keymanager.domain.port.KeyAuditPort;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GenerateHolderKeyUseCaseTest {

    private static final String TENANT = "tenant-1";
    private static final String HOLDER = "holder-1";
    private static final String CREDENTIAL = "cred-1";
    private static final String ISSUER = "https://issuer.example.com";

    @Mock private HolderKeyWritePort writePort;
    @Mock private KeyAuditPort auditPort;

    private GenerateHolderKeyUseCase useCase;

    @BeforeEach
    void setUp() {
        AlgorithmNegotiator negotiator = new AlgorithmNegotiator();
        HolderKeyFactory factory = new HolderKeyFactory();
        IssuanceProofSigner signer = new IssuanceProofSigner(new ObjectMapper());
        useCase = new GenerateHolderKeyUseCase(negotiator, factory, writePort, signer, auditPort);

        lenient().when(auditPort.emit(any())).thenReturn(Mono.empty());
    }

    private GenerateHolderKeyCommand command(List<String> algs) {
        return new GenerateHolderKeyCommand(
                TENANT, HOLDER, CREDENTIAL, CredentialFormat.SD_JWT_VC,
                algs, ISSUER, "nonce-xyz");
    }

    // --- happy path: new key ---

    @Test
    void execute_newKey_returnsCreatedTrue() {
        when(writePort.upsertIfAbsent(any())).thenAnswer(inv -> {
            HolderKey key = inv.getArgument(0);
            return Mono.just(new HolderKeyPersistResult(true, key));
        });

        StepVerifier.create(useCase.execute(command(List.of("ES256"))))
                .assertNext(result -> {
                    assertThat(result.created()).isTrue();
                    assertThat(result.publicJwk()).isNotNull();
                    assertThat(result.jwsProof()).isNotNull();
                    assertThat(result.keyId()).isNotNull();
                })
                .verifyComplete();
    }

    @Test
    void execute_newKey_preferredAlgorithmIsEdDSA() {
        when(writePort.upsertIfAbsent(any())).thenAnswer(inv -> {
            HolderKey key = inv.getArgument(0);
            return Mono.just(new HolderKeyPersistResult(true, key));
        });

        // issuer supports all three; EdDSA has highest preference per ADR-024
        StepVerifier.create(useCase.execute(command(List.of("EdDSA", "ES384", "ES256"))))
                .assertNext(result -> {
                    assertThat(result.jwsProof().algorithm().getJwsAlgorithmName()).isEqualTo("EdDSA");
                })
                .verifyComplete();
    }

    // --- happy path: existing key fetched (EC-01) ---

    @Test
    void execute_existingKey_returnsCreatedFalse() {
        // upsert returns the candidate as the existing key (created=false)
        when(writePort.upsertIfAbsent(any())).thenAnswer(inv -> {
            HolderKey candidate = inv.getArgument(0);
            return Mono.just(new HolderKeyPersistResult(false, candidate));
        });

        StepVerifier.create(useCase.execute(command(List.of("ES256"))))
                .assertNext(result -> {
                    assertThat(result.created()).isFalse();
                    assertThat(result.jwsProof()).isNotNull();
                })
                .verifyComplete();
    }

    // --- algorithm negotiation: no supported algorithm (AC-03) ---

    @Test
    void execute_noSupportedAlgorithm_throwsUnsupportedJwsAlgorithmException() {
        StepVerifier.create(useCase.execute(command(List.of("RS256", "PS256"))))
                .verifyError(UnsupportedJwsAlgorithmException.class);
    }

    // --- DB unavailable (AC-06) ---

    @Test
    void execute_dbWriteFails_propagatesError() {
        when(writePort.upsertIfAbsent(any()))
                .thenReturn(Mono.error(new RuntimeException("DB unavailable")));

        StepVerifier.create(useCase.execute(command(List.of("ES256"))))
                .verifyError(RuntimeException.class);
    }

    // --- audit failure does not fail main flow (AD-119-3) ---

    @Test
    void execute_auditEmitFails_resultIsStillReturned() {
        when(writePort.upsertIfAbsent(any())).thenAnswer(inv -> {
            HolderKey key = inv.getArgument(0);
            return Mono.just(new HolderKeyPersistResult(true, key));
        });
        when(auditPort.emit(any())).thenReturn(Mono.error(new RuntimeException("audit down")));

        StepVerifier.create(useCase.execute(command(List.of("ES256"))))
                .assertNext(result -> assertThat(result.created()).isTrue())
                .verifyComplete();
    }

    // --- audit event type (AD-119-3) ---

    @Test
    void execute_newKey_emitsKeyGeneratedAuditEvent() {
        when(writePort.upsertIfAbsent(any())).thenAnswer(inv -> {
            HolderKey key = inv.getArgument(0);
            return Mono.just(new HolderKeyPersistResult(true, key));
        });

        StepVerifier.create(useCase.execute(command(List.of("ES256"))))
                .expectNextCount(1)
                .verifyComplete();

        verify(auditPort).emit(argThat(event ->
                event.type() == KeyAuditEvent.KeyAuditEventType.KEY_GENERATED
                        && TENANT.equals(event.tenantId())
                        && CREDENTIAL.equals(event.credentialId())
        ));
    }

    @Test
    void execute_existingKey_emitsKeyFetchedAuditEvent() {
        when(writePort.upsertIfAbsent(any())).thenAnswer(inv -> {
            HolderKey candidate = inv.getArgument(0);
            return Mono.just(new HolderKeyPersistResult(false, candidate));
        });

        StepVerifier.create(useCase.execute(command(List.of("ES256"))))
                .expectNextCount(1)
                .verifyComplete();

        verify(auditPort).emit(argThat(event ->
                event.type() == KeyAuditEvent.KeyAuditEventType.KEY_FETCHED
        ));
    }

    // --- cNonce absent (EC-05) ---

    @Test
    void execute_withoutCNonce_completes() {
        GenerateHolderKeyCommand cmd = new GenerateHolderKeyCommand(
                TENANT, HOLDER, CREDENTIAL, CredentialFormat.SD_JWT_VC,
                List.of("ES256"), ISSUER, null);
        when(writePort.upsertIfAbsent(any())).thenAnswer(inv -> {
            HolderKey key = inv.getArgument(0);
            return Mono.just(new HolderKeyPersistResult(true, key));
        });

        StepVerifier.create(useCase.execute(cmd))
                .assertNext(result -> assertThat(result.created()).isTrue())
                .verifyComplete();
    }

}