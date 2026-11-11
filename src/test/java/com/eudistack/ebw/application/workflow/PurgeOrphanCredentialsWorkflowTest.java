package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static com.eudistack.ebw.application.workflow.CredentialWorkflowFixtures.credential;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PurgeOrphanCredentialsWorkflow} (EUD-328 FR-25).
 */
@ExtendWith(MockitoExtension.class)
class PurgeOrphanCredentialsWorkflowTest {

    private static final Instant NOW = Instant.parse("2026-11-10T03:30:00Z");
    private static final Map<String, Object> REASON = Map.of("reason", "orphan_expired");

    @Mock private PasskeyCustodyPolicy custodyPolicy;
    @Mock private WalletCredentialRepository credentialRepository;
    @Mock private CredentialRemover credentialRemover;

    private PurgeOrphanCredentialsWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new PurgeOrphanCredentialsWorkflow(custodyPolicy, credentialRepository, credentialRemover);
    }

    @Nested
    @DisplayName("purgeExpiredOrphans")
    class PurgeExpiredOrphans {

        @Test
        @DisplayName("with passkey custody it removes every expired orphan, with the audit reason")
        void purgeExpiredOrphans_passkeyCustody_removesEveryExpiredOrphan() {
            // Arrange
            var first = credential(UUID.randomUUID(), UUID.randomUUID(), CredentialStatus.VALID);
            var second = credential(UUID.randomUUID(), UUID.randomUUID(), CredentialStatus.REVOKED);
            when(custodyPolicy.isPasskeyCustody()).thenReturn(Mono.just(true));
            when(credentialRepository.findOrphanedExpired(NOW)).thenReturn(Flux.just(first, second));
            when(credentialRemover.remove(first, REASON)).thenReturn(Mono.empty());
            when(credentialRemover.remove(second, REASON)).thenReturn(Mono.empty());

            // Act
            var result = workflow.purgeExpiredOrphans(NOW);

            // Assert
            StepVerifier.create(result).expectNext(2L).verifyComplete();
            verify(credentialRemover).remove(first, REASON);
            verify(credentialRemover).remove(second, REASON);
        }

        @Test
        @DisplayName("with server custody it deletes nothing and does not query the orphans")
        void purgeExpiredOrphans_serverCustody_deletesNothing() {
            // Arrange
            when(custodyPolicy.isPasskeyCustody()).thenReturn(Mono.just(false));

            // Act
            var result = workflow.purgeExpiredOrphans(NOW);

            // Assert
            StepVerifier.create(result).expectNext(0L).verifyComplete();
            verifyNoInteractions(credentialRepository, credentialRemover);
        }

        @Test
        @DisplayName("without expired orphans it deletes nothing")
        void purgeExpiredOrphans_noExpiredOrphans_deletesNothing() {
            // Arrange
            when(custodyPolicy.isPasskeyCustody()).thenReturn(Mono.just(true));
            when(credentialRepository.findOrphanedExpired(NOW)).thenReturn(Flux.empty());

            // Act
            var result = workflow.purgeExpiredOrphans(NOW);

            // Assert
            StepVerifier.create(result).expectNext(0L).verifyComplete();
            verify(credentialRemover, never()).remove(any(), any());
        }

        @Test
        @DisplayName("a failure on one orphan does not stop the others and is not counted")
        void purgeExpiredOrphans_oneRemovalFails_continuesWithTheRest() {
            // Arrange
            var failing = credential(UUID.randomUUID(), UUID.randomUUID(), CredentialStatus.VALID);
            var healthy = credential(UUID.randomUUID(), UUID.randomUUID(), CredentialStatus.VALID);
            when(custodyPolicy.isPasskeyCustody()).thenReturn(Mono.just(true));
            when(credentialRepository.findOrphanedExpired(NOW)).thenReturn(Flux.just(failing, healthy));
            when(credentialRemover.remove(failing, REASON)).thenReturn(Mono.error(new IllegalStateException("db down")));
            when(credentialRemover.remove(healthy, REASON)).thenReturn(Mono.empty());

            // Act
            var result = workflow.purgeExpiredOrphans(NOW);

            // Assert
            StepVerifier.create(result).expectNext(1L).verifyComplete();
            verify(credentialRemover).remove(healthy, REASON);
        }
    }
}
