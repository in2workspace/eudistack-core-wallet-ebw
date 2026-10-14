package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.AuthTokenSettings;
import com.eudistack.ebw.domain.model.IssuedSession;
import com.eudistack.ebw.domain.model.RefreshToken;
import com.eudistack.ebw.domain.model.SessionSettings;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.model.exception.InvalidSessionException;
import com.eudistack.ebw.domain.model.exception.SessionExpiredException;
import com.eudistack.ebw.domain.model.exception.TokenFamilyCompromisedException;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.spi.HashProvider;
import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
import com.eudistack.ebw.domain.spi.TokenSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

/**
 * Sessions of the wallet. A session is a family of rotating refresh tokens that share a
 * {@code session_id}; it is opened only after a verified passkey and bound to the account and
 * to that passkey.
 *
 * <ul>
 *   <li>Access token: ES256 JWT with {@code sub}, {@code email}, {@code tenant}, {@code sid},
 *       {@code pkid}, {@code iss}, {@code iat}, {@code exp}.</li>
 *   <li>Refresh token: opaque, rotated on every renewal, expires the tenant's inactivity
 *       period after it is issued, never past the session's maximum duration. Presenting an
 *       already rotated token ends the whole session (RFC 9700 reuse detection).</li>
 * </ul>
 */
public class AuthTokenService {

    private static final Logger log = LoggerFactory.getLogger(AuthTokenService.class);
    private static final int REFRESH_TOKEN_BYTES = 32;

    private final TokenSigner tokenSigner;
    private final HashProvider hashProvider;
    private final SecureRandomGenerator randomGenerator;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserPasskeyRepository userPasskeyRepository;
    private final Duration accessTokenTtl;
    private final String issuer;

    public AuthTokenService(TokenSigner tokenSigner,
                            HashProvider hashProvider,
                            SecureRandomGenerator randomGenerator,
                            RefreshTokenRepository refreshTokenRepository,
                            UserPasskeyRepository userPasskeyRepository,
                            AuthTokenSettings settings) {
        this.tokenSigner = tokenSigner;
        this.hashProvider = hashProvider;
        this.randomGenerator = randomGenerator;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userPasskeyRepository = userPasskeyRepository;
        this.accessTokenTtl = settings.accessTokenTtl();
        this.issuer = settings.issuer();
    }

    /** Opens a new session for the account, bound to the passkey that was just verified. */
    public Mono<IssuedSession> openSession(WalletUser user, UUID passkeyId, SessionSettings settings, String tenant) {
        var now = Instant.now();
        return issue(user, passkeyId, randomGenerator.generateUuid(), now, now, settings, tenant);
    }

    /**
     * Renews the session of a refresh token: rotates it and issues a new access token.
     *
     * @throws InvalidSessionException          (signal) the token is not the account's
     * @throws TokenFamilyCompromisedException  (signal) the token was already rotated or ended;
     *                                          the whole session is ended
     * @throws SessionExpiredException          (signal) inactivity period or maximum duration reached
     */
    public Mono<IssuedSession> rotateRefreshToken(RefreshToken existing, WalletUser user, SessionSettings settings,
                                                  String tenant) {
        if (!existing.getUserId().equals(user.getId())) {
            return Mono.error(new InvalidSessionException());
        }
        var now = Instant.now();
        if (existing.isRevoked()) {
            return rejectRevoked(existing);
        }
        if (existing.isPastMaxDuration(now, settings.maxDuration())) {
            return refreshTokenRepository.revokeBySessionId(existing.getSessionId())
                    .then(Mono.error(new SessionExpiredException(existing.getSessionId(), user.getId(),
                            SessionExpiredException.Reason.MAX_DURATION)));
        }
        if (existing.isExpired(now)) {
            return refreshTokenRepository.revokeBySessionId(existing.getSessionId())
                    .then(Mono.error(new SessionExpiredException(existing.getSessionId(), user.getId(),
                            SessionExpiredException.Reason.IDLE_TIMEOUT)));
        }
        return refreshTokenRepository.revokeIfActive(existing.getId())
                .flatMap(revoked -> {
                    if (!Boolean.TRUE.equals(revoked)) {
                        // Another request rotated it first: the same token was presented twice.
                        return rejectRevoked(existing);
                    }
                    return touchPasskey(existing.getPasskeyId())
                            .then(issue(user, existing.getPasskeyId(), existing.getSessionId(),
                                    existing.getSessionStartedAt(), now, settings, tenant));
                });
    }

    /** Finds the refresh token of a raw cookie value. */
    public Mono<RefreshToken> findRefreshToken(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return Mono.empty();
        }
        return refreshTokenRepository.findByTokenHash(hashProvider.sha256(rawToken));
    }

    /** Ends a session: none of its tokens can be renewed any more. */
    public Mono<Void> endSession(UUID sessionId) {
        return refreshTokenRepository.revokeBySessionId(sessionId);
    }

    /** Ends every session of the account except the given one. Emits the number of revoked tokens. */
    public Mono<Long> endOtherSessions(UUID userId, UUID keptSessionId) {
        return refreshTokenRepository.revokeByUserIdExceptSession(userId, keptSessionId);
    }

    private Mono<IssuedSession> issue(WalletUser user, UUID passkeyId, UUID sessionId, Instant sessionStartedAt,
                                      Instant now, SessionSettings settings, String tenant) {
        var accessExp = now.plus(accessTokenTtl);
        var claims = Map.<String, Object>of(
                "sub", user.getId().toString(),
                "email", user.getEmail(),
                "tenant", tenant,
                "sid", sessionId.toString(),
                "pkid", passkeyId.toString(),
                "iss", issuer,
                "iat", now.getEpochSecond(),
                "exp", accessExp.getEpochSecond()
        );
        var accessToken = tokenSigner.sign(claims);

        var sessionExpiresAt = sessionStartedAt.plus(settings.maxDuration());
        var idleExpiresAt = now.plus(settings.idleTimeout());
        var refreshExpiresAt = idleExpiresAt.isBefore(sessionExpiresAt) ? idleExpiresAt : sessionExpiresAt;

        var rawRefreshToken = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(randomGenerator.generateBytes(REFRESH_TOKEN_BYTES));
        var refreshToken = RefreshToken.create(user.getId(), passkeyId, sessionId, sessionStartedAt,
                hashProvider.sha256(rawRefreshToken), refreshExpiresAt);

        return refreshTokenRepository.insert(refreshToken)
                .thenReturn(new IssuedSession(accessToken, accessTokenTtl.toSeconds(), rawRefreshToken,
                        sessionId, passkeyId, sessionExpiresAt));
    }

    /**
     * A revoked token is a reuse only while its session can still be renewed with another token
     * (RFC 9700): then the whole session is ended. A token of an already ended or expired session
     * is just an invalid session, without the reuse alarm.
     */
    private <T> Mono<T> rejectRevoked(RefreshToken existing) {
        return refreshTokenRepository.hasActiveToken(existing.getSessionId())
                .flatMap(active -> Boolean.TRUE.equals(active)
                        ? this.<T>endFamilyOnReuse(existing)
                        : Mono.<T>error(new InvalidSessionException()));
    }

    private <T> Mono<T> endFamilyOnReuse(RefreshToken existing) {
        log.warn("Refresh token reuse detected; ending session {}", existing.getSessionId());
        return refreshTokenRepository.revokeBySessionId(existing.getSessionId())
                .then(Mono.error(new TokenFamilyCompromisedException(existing.getSessionId(), existing.getUserId())));
    }

    /**
     * Records device activity for the devices list: a session renewal means the device behind
     * this passkey is in use. Best-effort: never fails the renewal.
     */
    private Mono<Void> touchPasskey(UUID passkeyId) {
        return Mono.defer(() -> userPasskeyRepository.touchLastUsed(passkeyId))
                .doOnError(e -> log.warn("Could not record last_used_at for passkey {}: {}", passkeyId, e.toString()))
                .onErrorResume(e -> Mono.empty());
    }
}
