package com.eudistack.ebw.keymanager.infrastructure.adapter.service;

import com.eudistack.ebw.keymanager.application.GenerateHolderKeyUseCase;
import com.eudistack.ebw.keymanager.application.SignHolderKeyUseCase;
import com.eudistack.ebw.keymanager.domain.model.ConsumerOrigin;
import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.GenerateHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyId;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyResult;
import com.eudistack.ebw.keymanager.domain.model.JwkPublic;
import com.eudistack.ebw.keymanager.domain.model.JwsProof;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.model.SignHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.SignHolderKeyResult;
import com.eudistack.ebw.keymanager.domain.model.SignaturePurpose;
import com.eudistack.ebw.keymanager.domain.model.SigningType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DbKeyManagerServiceTest {

    @Mock private GenerateHolderKeyUseCase useCase;
    @Mock private SignHolderKeyUseCase signUseCase;

    private DbKeyManagerService service;

    @BeforeEach
    void setUp() {
        service = new DbKeyManagerService(useCase, signUseCase);
    }

    private GenerateHolderKeyCommand anyCommand() {
        return new GenerateHolderKeyCommand(
                "tenant", "holder", "cred",
                CredentialFormat.SD_JWT_VC,
                List.of("ES256"),
                "https://issuer.example.com",
                null);
    }

    private HolderKeyResult fakeResult() {
        JwkPublic jwk = new JwkPublic(
                Map.of("kty", "EC", "crv", "P-256", "x", "abc", "y", "def"));
        JwsProof proof = new JwsProof("aaa.bbb.ccc", KeyAlgorithm.ES256);
        return new HolderKeyResult(HolderKeyId.generate(), jwk, proof, true);
    }

    // --- timeout constant ---

    @Test
    void generateTimeout_is_2500ms() {
        assertThat(DbKeyManagerService.GENERATE_TIMEOUT).isEqualTo(Duration.ofMillis(2500));
    }

    // --- delegation ---

    @Test
    void generateHolderKey_delegatesToUseCase() {
        HolderKeyResult expected = fakeResult();
        when(useCase.execute(any())).thenReturn(Mono.just(expected));

        StepVerifier.create(service.generateHolderKey(anyCommand()))
                .assertNext(result -> assertThat(result).isSameAs(expected))
                .verifyComplete();
    }

    // --- timeout (ES-04 / NFR-P-119-01) ---

    @Test
    void generateHolderKey_exceedsTimeout_emitsTimeoutException() {
        when(useCase.execute(any())).thenReturn(Mono.never());

        StepVerifier.withVirtualTime(() -> service.generateHolderKey(anyCommand()))
                .thenAwait(DbKeyManagerService.GENERATE_TIMEOUT.plusMillis(100))
                .expectError(java.util.concurrent.TimeoutException.class)
                .verify();
    }

    @Test
    void generateHolderKey_completesBeforeTimeout_succeeds() {
        HolderKeyResult expected = fakeResult();
        when(useCase.execute(any())).thenReturn(Mono.just(expected));

        StepVerifier.withVirtualTime(() -> service.generateHolderKey(anyCommand()))
                .thenAwait(Duration.ofMillis(100))
                .expectNextCount(1)
                .verifyComplete();
    }

    // --- signWithHolderKey delegation ---

    @Test
    void signWithHolderKey_delegatesToSignUseCase() {
        // Given
        SignHolderKeyResult expected = new SignHolderKeyResult("h.p.s", KeyAlgorithm.ES256, "jkt-abc");
        when(signUseCase.execute(any())).thenReturn(Mono.just(expected));
        SignHolderKeyCommand cmd = new SignHolderKeyCommand(
                HolderKeyId.generate(), "tenant", "holder",
                SigningType.KB_JWT, SignaturePurpose.PRESENTATION, ConsumerOrigin.SYSTEM,
                new byte[]{1, 2, 3});

        // When / Then
        StepVerifier.create(service.signWithHolderKey(cmd))
                .assertNext(result -> assertThat(result).isSameAs(expected))
                .verifyComplete();
    }
}
