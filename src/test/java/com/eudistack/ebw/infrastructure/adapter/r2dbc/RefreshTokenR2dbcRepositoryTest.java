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
 * Unit tests for {@link RefreshTokenR2dbcRepository}: insert dispatch, mapping and delegation of the
 * revocation queries (whose SQL is covered by the session integration tests).
 */
class RefreshTokenR2dbcRepositoryTest {

    private SpringRefreshTokenRepository springRepository;
    private RefreshTokenR2dbcRepository repository;

    @BeforeEach
    void setUp() {
        springRepository = mock(SpringRefreshTokenRepository.class);
        repository = new RefreshTokenR2dbcRepository(springRepository);
    }

    private static RefreshToken token() {
        return RefreshToken.create(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), Instant.now(), "hash",
                Instant.now().plusSeconds(60));
    }

    @Test
    void insert_newToken_savesAnEntityMarkedNewAndMapsItBack() {
        // Arrange
        var token = token();
        when(springRepository.save(any(RefreshTokenEntity.class))).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Act
        var result = repository.insert(token);

        // Assert
        StepVerifier.create(result)
                .assertNext(saved -> assertThat(saved).usingRecursiveComparison().isEqualTo(token))
                .verifyComplete();
        var saved = ArgumentCaptor.forClass(RefreshTokenEntity.class);
        verify(springRepository).save(saved.capture());
        assertThat(saved.getValue().isNew()).isTrue();
    }

    @Test
    void findByTokenHash_existingRow_mapsSessionFields() {
        // Arrange
        var token = token();
        when(springRepository.findByTokenHash("hash")).thenReturn(Mono.just(RefreshTokenMapper.toEntity(token)));

        // Act
        var result = repository.findByTokenHash("hash");

        // Assert
        StepVerifier.create(result)
                .assertNext(found -> {
                    assertThat(found.getSessionId()).isEqualTo(token.getSessionId());
                    assertThat(found.getSessionStartedAt()).isEqualTo(token.getSessionStartedAt());
                    assertThat(found.getPasskeyId()).isEqualTo(token.getPasskeyId());
                })
                .verifyComplete();
    }

    @Test
    void revokeIfActive_oneRowUpdated_emitsTrue() {
        // Arrange
        var id = UUID.randomUUID();
        when(springRepository.revokeIfActive(id)).thenReturn(Mono.just(1L));

        // Act + Assert
        StepVerifier.create(repository.revokeIfActive(id)).expectNext(true).verifyComplete();
    }

    @Test
    void revokeIfActive_noRowUpdated_emitsFalse() {
        // Arrange
        var id = UUID.randomUUID();
        when(springRepository.revokeIfActive(id)).thenReturn(Mono.just(0L));

        // Act + Assert
        StepVerifier.create(repository.revokeIfActive(id)).expectNext(false).verifyComplete();
    }

    @Test
    void revocationQueries_delegateToSpringData() {
        // Arrange
        var passkeyId = UUID.randomUUID();
        var sessionId = UUID.randomUUID();
        var userId = UUID.randomUUID();
        when(springRepository.revokeByPasskeyId(passkeyId)).thenReturn(Mono.empty());
        when(springRepository.revokeBySessionId(sessionId)).thenReturn(Mono.just(2L));
        when(springRepository.revokeByUserIdExceptSession(userId, sessionId)).thenReturn(Mono.just(3L));
        when(springRepository.countActiveByPasskeyId(passkeyId)).thenReturn(Mono.just(4L));

        // Act + Assert
        StepVerifier.create(repository.revokeByPasskeyId(passkeyId)).verifyComplete();
        StepVerifier.create(repository.revokeBySessionId(sessionId)).verifyComplete();
        StepVerifier.create(repository.revokeByUserIdExceptSession(userId, sessionId)).expectNext(3L).verifyComplete();
        StepVerifier.create(repository.countActiveByPasskeyId(passkeyId)).expectNext(4L).verifyComplete();
        verify(springRepository).revokeBySessionId(sessionId);
    }
}
