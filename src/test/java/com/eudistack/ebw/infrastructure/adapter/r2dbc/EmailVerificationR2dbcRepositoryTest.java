package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.EmailVerificationEntity;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.spring.SpringEmailVerificationRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
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
}
