package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.EmailVerification;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.EmailVerificationEntity;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.spring.SpringEmailVerificationRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link EmailVerificationR2dbcRepository#findLatestUnusedByEmail}. The query
 * itself (latest unused row, no expiry filter) is exercised against PostgreSQL by
 * {@code AuthFlowIntegrationTest}; here the Spring Data repository is mocked.
 */
class EmailVerificationR2dbcRepositoryTest {

    private SpringEmailVerificationRepository springRepository;
    private EmailVerificationR2dbcRepository repository;

    @BeforeEach
    void setUp() {
        springRepository = mock(SpringEmailVerificationRepository.class);
        repository = new EmailVerificationR2dbcRepository(springRepository);
    }

    @Test
    void findLatestUnusedByEmail_expiredRow_isReturnedAndMapped() {
        // Arrange: #1061173 — an expired row must reach OtpService, not be filtered out
        var email = "user@example.com";
        var id = UUID.randomUUID();
        var expiresAt = Instant.now().minusSeconds(60);
        var createdAt = Instant.now().minusSeconds(660);
        var entity = new EmailVerificationEntity(id, email, "bcrypt-hash", 2, expiresAt, false, createdAt);
        when(springRepository.findFirstByUserEmailAndUsedFalseOrderByCreatedAtDesc(email))
                .thenReturn(Mono.just(entity));

        // Act & Assert
        StepVerifier.create(repository.findLatestUnusedByEmail(email))
                .assertNext(verification -> {
                    assertThat(verification.getId()).isEqualTo(id);
                    assertThat(verification.getUserEmail()).isEqualTo(email);
                    assertThat(verification.getCodeHash()).isEqualTo("bcrypt-hash");
                    assertThat(verification.getAttempts()).isEqualTo(2);
                    assertThat(verification.getExpiresAt()).isEqualTo(expiresAt);
                    assertThat(verification.isUsed()).isFalse();
                    assertThat(verification.getCreatedAt()).isEqualTo(createdAt);
                    assertThat(verification.isExpired()).isTrue();
                })
                .verifyComplete();
    }

    @Test
    void findLatestUnusedByEmail_noRow_completesEmpty() {
        // Arrange
        var email = "user@example.com";
        when(springRepository.findFirstByUserEmailAndUsedFalseOrderByCreatedAtDesc(email))
                .thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(repository.findLatestUnusedByEmail(email))
                .verifyComplete();
    }

    @Test
    void save_newVerification_insertsAnEntityMarkedNew() {
        // Arrange
        var verification = new EmailVerification(UUID.randomUUID(), "user@example.com", "hash", 0,
                Instant.now().plusSeconds(600), false, Instant.now());
        when(springRepository.existsById(verification.getId())).thenReturn(Mono.just(false));
        when(springRepository.save(any(EmailVerificationEntity.class))).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Act
        var result = repository.save(verification);

        // Assert
        StepVerifier.create(result)
                .assertNext(saved -> assertThat(saved).usingRecursiveComparison().isEqualTo(verification))
                .verifyComplete();
        var saved = ArgumentCaptor.forClass(EmailVerificationEntity.class);
        verify(springRepository).save(saved.capture());
        assertThat(saved.getValue().isNew()).isTrue();
    }

    @Test
    void save_existingVerification_updatesWithoutMarkingNew() {
        // Arrange
        var verification = new EmailVerification(UUID.randomUUID(), "user@example.com", "hash", 3,
                Instant.now().plusSeconds(600), true, Instant.now());
        when(springRepository.existsById(verification.getId())).thenReturn(Mono.just(true));
        when(springRepository.save(any(EmailVerificationEntity.class))).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Act
        var result = repository.save(verification);

        // Assert
        StepVerifier.create(result).expectNextCount(1).verifyComplete();
        var saved = ArgumentCaptor.forClass(EmailVerificationEntity.class);
        verify(springRepository).save(saved.capture());
        assertThat(saved.getValue().isNew()).isFalse();
        assertThat(saved.getValue().getAttempts()).isEqualTo(3);
    }

    @Test
    void invalidateByEmail_delegatesToSpringData() {
        // Arrange
        when(springRepository.invalidateByEmail("user@example.com")).thenReturn(Mono.empty());

        // Act
        var result = repository.invalidateByEmail("user@example.com");

        // Assert
        StepVerifier.create(result).verifyComplete();
        verify(springRepository).invalidateByEmail("user@example.com");
    }
}
