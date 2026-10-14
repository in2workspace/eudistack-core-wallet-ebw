package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.RefreshToken;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.RefreshTokenEntity;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper.RefreshTokenMapper;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.spring.SpringRefreshTokenRepository;
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
 * Unit tests for {@link RefreshTokenR2dbcRepository} — insert-vs-update dispatch and delegation of the
 * revocation / attribution queries (whose SQL is covered by the auth integration tests).
 */
class RefreshTokenR2dbcRepositoryTest {

    private SpringRefreshTokenRepository springRepository;
    private RefreshTokenR2dbcRepository repository;

    @BeforeEach
    void setUp() {
        springRepository = mock(SpringRefreshTokenRepository.class);
        repository = new RefreshTokenR2dbcRepository(springRepository);
    }

    @Test
    void save_newToken_insertsAnEntityMarkedNewAndMapsItBack() {
        // Arrange
        var token = RefreshToken.create(UUID.randomUUID(), UUID.randomUUID(), "hash", Instant.now().plusSeconds(60));
        when(springRepository.existsById(token.getId())).thenReturn(Mono.just(false));
        when(springRepository.save(any(RefreshTokenEntity.class))).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Act
        var result = repository.save(token);

        // Assert
        StepVerifier.create(result)
                .assertNext(saved -> assertThat(saved).usingRecursiveComparison().isEqualTo(token))
                .verifyComplete();
        var saved = ArgumentCaptor.forClass(RefreshTokenEntity.class);
        verify(springRepository).save(saved.capture());
        assertThat(saved.getValue().isNew()).isTrue();
    }

    @Test
    void save_existingToken_updatesWithoutMarkingNew() {
        // Arrange
        var token = RefreshToken.create(UUID.randomUUID(), null, "hash", Instant.now().plusSeconds(60));
        token.revoke();
        when(springRepository.existsById(token.getId())).thenReturn(Mono.just(true));
        when(springRepository.save(any(RefreshTokenEntity.class))).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Act
        var result = repository.save(token);

        // Assert
        StepVerifier.create(result).assertNext(saved -> assertThat(saved.isRevoked()).isTrue()).verifyComplete();
        var saved = ArgumentCaptor.forClass(RefreshTokenEntity.class);
        verify(springRepository).save(saved.capture());
        assertThat(saved.getValue().isNew()).isFalse();
    }

    @Test
    void findByTokenHash_existingRow_mapsItToTheDomain() {
        // Arrange
        var token = RefreshToken.create(UUID.randomUUID(), UUID.randomUUID(), "hash", Instant.now().plusSeconds(60));
        when(springRepository.findByTokenHash("hash")).thenReturn(Mono.just(RefreshTokenMapper.toEntity(token)));

        // Act
        var result = repository.findByTokenHash("hash");

        // Assert
        StepVerifier.create(result)
                .assertNext(found -> assertThat(found.getPasskeyId()).isEqualTo(token.getPasskeyId()))
                .verifyComplete();
    }

    @Test
    void revocationAndAttributionQueries_delegateToSpringData() {
        // Arrange
        var passkeyId = UUID.randomUUID();
        var userId = UUID.randomUUID();
        when(springRepository.revokeByPasskeyId(passkeyId)).thenReturn(Mono.empty());
        when(springRepository.revokeByUserId(userId)).thenReturn(Mono.empty());
        when(springRepository.countActiveByPasskeyId(passkeyId)).thenReturn(Mono.just(4L));
        when(springRepository.updatePasskeyIdByTokenHash("hash", passkeyId)).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(repository.revokeByPasskeyId(passkeyId)).verifyComplete();
        StepVerifier.create(repository.revokeByUserId(userId)).verifyComplete();
        StepVerifier.create(repository.countActiveByPasskeyId(passkeyId)).expectNext(4L).verifyComplete();
        StepVerifier.create(repository.updatePasskeyIdByTokenHash("hash", passkeyId)).verifyComplete();
        verify(springRepository).revokeByPasskeyId(passkeyId);
        verify(springRepository).revokeByUserId(userId);
        verify(springRepository).updatePasskeyIdByTokenHash("hash", passkeyId);
    }
}
