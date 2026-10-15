package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.ExpiredSession;
import com.eudistack.ebw.domain.model.RefreshToken;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper.RefreshTokenMapper;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.spring.SpringRefreshTokenRepository;
import io.r2dbc.spi.Readable;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

@Repository
public class RefreshTokenR2dbcRepository implements RefreshTokenRepository {

    /**
     * Revokes the still-unrevoked tokens of every session that has no token able to renew it, and
     * reports each of those sessions with the expiry of its last token. One statement: the
     * {@code revoked = false} condition is re-checked on the locked row, so when several instances
     * run it at once each token is revoked, and reported, by only one of them.
     */
    static final String EXPIRE_LAPSED_SESSIONS_SQL = """
            WITH lapsed AS (
                UPDATE refresh_token t SET revoked = true
                 WHERE t.revoked = false
                   AND t.expires_at <= now()
                   AND NOT EXISTS (SELECT 1 FROM refresh_token a
                                    WHERE a.session_id = t.session_id
                                      AND a.revoked = false
                                      AND a.expires_at > now())
                RETURNING t.session_id, t.user_id, t.session_started_at, t.expires_at
            )
            SELECT session_id, user_id, session_started_at, max(expires_at) AS last_expires_at
              FROM lapsed
             GROUP BY session_id, user_id, session_started_at
            """;

    private final SpringRefreshTokenRepository springRepository;
    private final DatabaseClient databaseClient;

    public RefreshTokenR2dbcRepository(SpringRefreshTokenRepository springRepository, DatabaseClient databaseClient) {
        this.springRepository = springRepository;
        this.databaseClient = databaseClient;
    }

    @Override
    public Mono<RefreshToken> findByTokenHash(String tokenHash) {
        return springRepository.findByTokenHash(tokenHash).map(RefreshTokenMapper::toDomain);
    }

    @Override
    public Mono<RefreshToken> insert(RefreshToken token) {
        var entity = RefreshTokenMapper.toEntity(token);
        entity.markNew();
        return springRepository.save(entity).map(RefreshTokenMapper::toDomain);
    }

    @Override
    public Mono<Void> deleteById(UUID id) {
        return springRepository.deleteById(id);
    }

    @Override
    public Mono<Boolean> revokeIfActive(UUID id) {
        return springRepository.revokeIfActive(id).map(rows -> rows > 0).defaultIfEmpty(false);
    }

    @Override
    public Mono<Boolean> hasActiveToken(UUID sessionId) {
        return springRepository.hasActiveToken(sessionId).defaultIfEmpty(false);
    }

    @Override
    public Mono<Long> revokeBySessionId(UUID sessionId) {
        return springRepository.revokeBySessionId(sessionId).defaultIfEmpty(0L);
    }

    @Override
    public Flux<ExpiredSession> expireLapsedSessions() {
        return databaseClient.sql(EXPIRE_LAPSED_SESSIONS_SQL)
                .map((row, metadata) -> toExpiredSession(row))
                .all();
    }

    @Override
    public Mono<Long> revokeByUserIdExceptSession(UUID userId, UUID keptSessionId) {
        return springRepository.revokeByUserIdExceptSession(userId, keptSessionId).defaultIfEmpty(0L);
    }

    @Override
    public Mono<Void> revokeByPasskeyId(UUID passkeyId) {
        return springRepository.revokeByPasskeyId(passkeyId);
    }

    @Override
    public Mono<Long> countActiveByPasskeyId(UUID passkeyId) {
        return springRepository.countActiveByPasskeyId(passkeyId);
    }

    @Override
    public Mono<Long> deleteSessionsEndedBefore(Instant cutoff) {
        return springRepository.deleteSessionsEndedBefore(cutoff).defaultIfEmpty(0L);
    }

    private static ExpiredSession toExpiredSession(Readable row) {
        return new ExpiredSession(
                row.get("session_id", UUID.class),
                row.get("user_id", UUID.class),
                row.get("session_started_at", Instant.class),
                row.get("last_expires_at", Instant.class));
    }
}
