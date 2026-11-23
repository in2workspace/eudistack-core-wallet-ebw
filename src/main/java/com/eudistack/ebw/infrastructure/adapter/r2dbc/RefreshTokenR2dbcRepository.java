package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.ExpiredSession;
import com.eudistack.ebw.domain.model.PendingPasskeyNotice;
import com.eudistack.ebw.domain.model.RefreshToken;
import com.eudistack.ebw.domain.model.SessionState;
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

    /**
     * Alive (a token that can renew it) and the active instance the family is bound to. The binding is read from
     * the most recent token of the family that carries one, so a token a concurrent rotation stored without it
     * does not hide it (EUD-15 AD-2); every token of a family carries the same instance (see BIND_SESSION_SQL).
     */
    static final String SESSION_STATE_SQL = """
            SELECT EXISTS (SELECT 1 FROM refresh_token a
                            WHERE a.session_id = :sessionId AND a.revoked = false AND a.expires_at > now()) AS active,
                   (SELECT wi.id FROM refresh_token t
                      JOIN wallet_instance wi ON wi.id = t.wallet_instance_id
                     WHERE t.session_id = :sessionId AND wi.status = 'ACTIVE'
                     ORDER BY t.created_at DESC
                     LIMIT 1) AS wallet_instance_id
            """;

    /**
     * Binds every token of the family, the rotated ones too: a family is bound to one instance only, so revoking
     * an instance it was bound to before never ends it (REVOKE_BY_INSTANCE_SQL).
     */
    static final String BIND_SESSION_SQL = """
            UPDATE refresh_token SET wallet_instance_id = :walletInstanceId WHERE session_id = :sessionId
            """;

    /**
     * A rotation copies the state of the token it replaces when it builds the new one; a binding or a cleared
     * notice that landed in between only reached the old token. Copies it again once both are stored.
     */
    static final String INHERIT_SESSION_STATE_SQL = """
            UPDATE refresh_token n SET wallet_instance_id = o.wallet_instance_id,
                                      passkey_notice_pending = o.passkey_notice_pending
              FROM refresh_token o
             WHERE n.id = :newId AND o.id = :previousId
            """;

    /** Every family with a token bound to the instance, not only its bound tokens (see the port). */
    static final String REVOKE_BY_INSTANCE_SQL = """
            UPDATE refresh_token SET revoked = true
             WHERE revoked = false
               AND session_id IN (SELECT session_id FROM refresh_token WHERE wallet_instance_id = :walletInstanceId)
            RETURNING session_id
            """;

    static final String MARK_NOTICE_SQL = """
            UPDATE refresh_token SET passkey_notice_pending = true WHERE session_id = :sessionId
            """;

    static final String CLEAR_NOTICE_SQL = """
            UPDATE refresh_token SET passkey_notice_pending = false
             WHERE session_id = :sessionId AND passkey_notice_pending = true
            """;

    /**
     * Clears the mark of the families with no token able to renew them any more and reports each one with the
     * registration time of its passkey. The {@code passkey_notice_pending = true} condition is re-checked on the
     * locked rows, so when several instances run it at once each session is reported by only one of them.
     */
    static final String TAKE_ENDED_NOTICES_SQL = """
            WITH taken AS (
                UPDATE refresh_token t SET passkey_notice_pending = false
                 WHERE t.passkey_notice_pending = true
                   AND NOT EXISTS (SELECT 1 FROM refresh_token a
                                    WHERE a.session_id = t.session_id
                                      AND a.revoked = false
                                      AND a.expires_at > now())
                RETURNING t.session_id, t.user_id, t.passkey_id
            )
            SELECT DISTINCT taken.session_id, taken.user_id, taken.passkey_id, p.created_at AS passkey_added_at
              FROM taken JOIN user_passkey p ON p.id = taken.passkey_id
            """;

    private static final String SESSION_ID = "sessionId";
    private static final String WALLET_INSTANCE_ID = "walletInstanceId";

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
    public Mono<Long> revokeByUserId(UUID userId) {
        return springRepository.revokeByUserId(userId).defaultIfEmpty(0L);
    }

    @Override
    public Mono<SessionState> findSessionState(UUID sessionId) {
        return databaseClient.sql(SESSION_STATE_SQL)
                .bind(SESSION_ID, sessionId)
                .map((row, metadata) -> new SessionState(Boolean.TRUE.equals(row.get("active", Boolean.class)),
                        row.get("wallet_instance_id", UUID.class)))
                .one()
                .map(state -> state.active() ? state : SessionState.ENDED)
                .defaultIfEmpty(SessionState.ENDED);
    }

    @Override
    public Mono<Long> bindSession(UUID sessionId, UUID walletInstanceId) {
        return databaseClient.sql(BIND_SESSION_SQL)
                .bind(SESSION_ID, sessionId)
                .bind(WALLET_INSTANCE_ID, walletInstanceId)
                .fetch().rowsUpdated();
    }

    @Override
    public Flux<UUID> revokeByWalletInstanceId(UUID walletInstanceId) {
        return databaseClient.sql(REVOKE_BY_INSTANCE_SQL)
                .bind(WALLET_INSTANCE_ID, walletInstanceId)
                .map((row, metadata) -> row.get("session_id", UUID.class))
                .all()
                .distinct();
    }

    @Override
    public Mono<Void> inheritSessionState(UUID newTokenId, UUID previousTokenId) {
        return databaseClient.sql(INHERIT_SESSION_STATE_SQL)
                .bind("newId", newTokenId)
                .bind("previousId", previousTokenId)
                .fetch().rowsUpdated().then();
    }

    @Override
    public Mono<Void> markPasskeyNoticePending(UUID sessionId) {
        return databaseClient.sql(MARK_NOTICE_SQL).bind(SESSION_ID, sessionId).fetch().rowsUpdated().then();
    }

    @Override
    public Mono<Boolean> clearPasskeyNoticePending(UUID sessionId) {
        return databaseClient.sql(CLEAR_NOTICE_SQL).bind(SESSION_ID, sessionId).fetch().rowsUpdated()
                .map(rows -> rows > 0)
                .defaultIfEmpty(false);
    }

    @Override
    public Flux<PendingPasskeyNotice> takePendingNoticesOfEndedSessions() {
        return databaseClient.sql(TAKE_ENDED_NOTICES_SQL)
                .map((row, metadata) -> new PendingPasskeyNotice(
                        row.get("session_id", UUID.class),
                        row.get("user_id", UUID.class),
                        row.get("passkey_id", UUID.class),
                        row.get("passkey_added_at", Instant.class)))
                .all();
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
