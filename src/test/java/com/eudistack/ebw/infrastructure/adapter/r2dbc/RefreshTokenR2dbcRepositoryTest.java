package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.ExpiredSession;
import com.eudistack.ebw.domain.model.RefreshToken;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.RefreshTokenEntity;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper.RefreshTokenMapper;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.spring.SpringRefreshTokenRepository;
import io.r2dbc.spi.Row;
import io.r2dbc.spi.RowMetadata;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.r2dbc.core.RowsFetchSpec;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.UUID;
import java.util.function.BiFunction;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link RefreshTokenR2dbcRepository}: insert dispatch, mapping and delegation of the
 * revocation queries (whose SQL is covered by the session integration tests).
 */
class RefreshTokenR2dbcRepositoryTest {

    private SpringRefreshTokenRepository springRepository;
    private DatabaseClient databaseClient;
    private RefreshTokenR2dbcRepository repository;

    @BeforeEach
    void setUp() {
        springRepository = mock(SpringRefreshTokenRepository.class);
        databaseClient = mock(DatabaseClient.class);
        repository = new RefreshTokenR2dbcRepository(springRepository, databaseClient);
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
        StepVerifier.create(repository.revokeBySessionId(sessionId)).expectNext(2L).verifyComplete();
        StepVerifier.create(repository.revokeByUserIdExceptSession(userId, sessionId)).expectNext(3L).verifyComplete();
        StepVerifier.create(repository.countActiveByPasskeyId(passkeyId)).expectNext(4L).verifyComplete();
        verify(springRepository).revokeBySessionId(sessionId);
    }

    @Test
    void revokeBySessionId_nothingReported_emitsZero() {
        // Arrange
        var sessionId = UUID.randomUUID();
        when(springRepository.revokeBySessionId(sessionId)).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(repository.revokeBySessionId(sessionId)).expectNext(0L).verifyComplete();
    }

    @Test
    @SuppressWarnings("unchecked")
    void expireLapsedSessions_closedSessions_runsTheConditionalUpdateAndMapsEachRow() {
        // Arrange
        var sessionId = UUID.randomUUID();
        var userId = UUID.randomUUID();
        var startedAt = Instant.parse("2026-10-15T08:00:00Z");
        var lastExpiresAt = Instant.parse("2026-10-15T09:00:00Z");
        var row = mock(Row.class);
        when(row.get("session_id", UUID.class)).thenReturn(sessionId);
        when(row.get("user_id", UUID.class)).thenReturn(userId);
        when(row.get("session_started_at", Instant.class)).thenReturn(startedAt);
        when(row.get("last_expires_at", Instant.class)).thenReturn(lastExpiresAt);
        var spec = mock(DatabaseClient.GenericExecuteSpec.class);
        when(databaseClient.sql(anyString())).thenReturn(spec);
        when(spec.map(any(BiFunction.class))).thenAnswer(inv -> {
            var mapper = (BiFunction<Row, RowMetadata, ExpiredSession>) inv.getArgument(0);
            RowsFetchSpec<ExpiredSession> rows = mock(RowsFetchSpec.class);
            when(rows.all()).thenReturn(Flux.defer(() -> Flux.just(mapper.apply(row, mock(RowMetadata.class)))));
            return rows;
        });

        // Act + Assert
        StepVerifier.create(repository.expireLapsedSessions())
                .expectNext(new ExpiredSession(sessionId, userId, startedAt, lastExpiresAt))
                .verifyComplete();
        verify(databaseClient).sql(RefreshTokenR2dbcRepository.EXPIRE_LAPSED_SESSIONS_SQL);
    }
}
