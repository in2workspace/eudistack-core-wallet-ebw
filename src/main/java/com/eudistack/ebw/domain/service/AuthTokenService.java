package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.AuthTokenPair;
import com.eudistack.ebw.domain.model.RefreshToken;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.model.exception.InvalidTokenException;
import com.eudistack.ebw.domain.model.exception.TokenFamilyCompromisedException;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.eudistack.ebw.domain.spi.HashProvider;
import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
import com.eudistack.ebw.domain.spi.TokenSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public class AuthTokenService {

    // DEBUG EUD-BUG-refresh-token: temporary diagnostic logging, remove before commit.
    private static final Logger log = LoggerFactory.getLogger(AuthTokenService.class);

    private final TokenSigner tokenSigner;
    private final HashProvider hashProvider;
    private final SecureRandomGenerator randomGenerator;
    private final RefreshTokenRepository refreshTokenRepository;
    private final Duration accessTokenTtl;
    private final Duration refreshTokenTtl;
    private final String issuer;

    public AuthTokenService(TokenSigner tokenSigner,
                            HashProvider hashProvider,
                            SecureRandomGenerator randomGenerator,
                            RefreshTokenRepository refreshTokenRepository,
                            Duration accessTokenTtl,
                            Duration refreshTokenTtl,
                            String issuer) {
        this.tokenSigner = tokenSigner;
        this.hashProvider = hashProvider;
        this.randomGenerator = randomGenerator;
        this.refreshTokenRepository = refreshTokenRepository;
        this.accessTokenTtl = accessTokenTtl;
        this.refreshTokenTtl = refreshTokenTtl;
        this.issuer = issuer;
    }

    public Mono<AuthTokenPair> issueTokenPair(WalletUser user, UUID passkeyId) {
        var now = Instant.now();
        var exp = now.plus(accessTokenTtl);

        var claims = Map.<String, Object>of(
                "sub", user.getId().toString(),
                "email", user.getEmail(),
                "iss", issuer,
                "iat", now.getEpochSecond(),
                "exp", exp.getEpochSecond()
        );

        var accessToken = tokenSigner.sign(claims);
        var rawRefreshToken = randomGenerator.generateUuid().toString();
        var tokenHash = hashProvider.sha256(rawRefreshToken);

        var refreshToken = RefreshToken.create(
                user.getId(), passkeyId, tokenHash, now.plus(refreshTokenTtl));

        log.info("DEBUG issueTokenPair: userId={} passkeyId={} newRawToken={} newTokenHash={}",
                user.getId(), passkeyId, rawRefreshToken, tokenHash);

        return refreshTokenRepository.save(refreshToken)
                .thenReturn(new AuthTokenPair(accessToken, rawRefreshToken, accessTokenTtl.toSeconds()));
    }

    public Map<String, Object> validateAccessToken(String token) {
        return tokenSigner.verify(token);
    }

    public Mono<AuthTokenPair> rotateRefreshToken(String rawToken, WalletUser user) {
        var tokenHash = hashProvider.sha256(rawToken);
        log.info("DEBUG rotateRefreshToken: incoming rawToken={} tokenHash={} userId={}",
                rawToken, tokenHash, user.getId());
        return refreshTokenRepository.findByTokenHash(tokenHash)
                .switchIfEmpty(Mono.defer(() -> {
                    log.warn("DEBUG rotateRefreshToken: NOT FOUND rawToken={} tokenHash={} userId={}",
                            rawToken, tokenHash, user.getId());
                    return Mono.error(new InvalidTokenException());
                }))
                .flatMap(existing -> {
                    log.info("DEBUG rotateRefreshToken: found row rawToken={} tokenHash={} userId={} passkeyId={} " +
                                    "revoked={} expiresAt={} createdAt={}",
                            rawToken, tokenHash, existing.getUserId(), existing.getPasskeyId(),
                            existing.isRevoked(), existing.getExpiresAt(), existing.getCreatedAt());
                    if (existing.isRevoked()) {
                        log.warn("DEBUG rotateRefreshToken: REUSE DETECTED (token_compromised) rawToken={} " +
                                        "tokenHash={} userId={} passkeyId={} -> cascading revoke by {}",
                                rawToken, tokenHash, existing.getUserId(), existing.getPasskeyId(),
                                existing.getPasskeyId() != null ? "passkeyId" : "userId (ALL DEVICES)");
                        var revoke = existing.getPasskeyId() != null
                                ? refreshTokenRepository.revokeByPasskeyId(existing.getPasskeyId())
                                : refreshTokenRepository.revokeByUserId(existing.getUserId());
                        return revoke.then(Mono.error(new TokenFamilyCompromisedException()));
                    }
                    if (existing.isExpired()) {
                        log.warn("DEBUG rotateRefreshToken: EXPIRED rawToken={} tokenHash={} userId={} expiresAt={}",
                                rawToken, tokenHash, existing.getUserId(), existing.getExpiresAt());
                        return Mono.error(new InvalidTokenException());
                    }
                    existing.revoke();
                    return refreshTokenRepository.save(existing)
                            .then(issueTokenPair(user, existing.getPasskeyId()))
                            .doOnNext(pair -> log.info("DEBUG rotateRefreshToken: SUCCESS oldRawToken={} oldTokenHash={} " +
                                            "userId={} passkeyId={} newRawToken={}",
                                    rawToken, tokenHash, existing.getUserId(), existing.getPasskeyId(),
                                    pair.refreshToken()));
                });
    }

    public Mono<Void> revokeRefreshToken(String rawToken) {
        var tokenHash = hashProvider.sha256(rawToken);
        return refreshTokenRepository.findByTokenHash(tokenHash)
                .flatMap(token -> {
                    token.revoke();
                    return refreshTokenRepository.save(token).then();
                })
                .then();
    }

    /**
     * Global logout: finds the token by hash, revokes ALL tokens for that user.
     * Returns the userId for audit purposes, or empty if token not found (idempotent).
     */
    public Mono<UUID> revokeAllByRefreshToken(String rawToken) {
        var tokenHash = hashProvider.sha256(rawToken);
        return refreshTokenRepository.findByTokenHash(tokenHash)
                .flatMap(token -> {
                    var userId = token.getUserId();
                    log.info("DEBUG revokeAllByRefreshToken: userId={} tokenHash={}", userId, tokenHash);
                    return refreshTokenRepository.revokeByUserId(userId)
                            .thenReturn(userId);
                });
    }

    public Mono<Void> revokeAllByUser(UUID userId) {
        log.info("DEBUG revokeAllByUser: userId={}", userId);
        return refreshTokenRepository.revokeByUserId(userId);
    }

    public Mono<Void> revokeAllByPasskey(UUID passkeyId) {
        log.info("DEBUG revokeAllByPasskey: passkeyId={}", passkeyId);
        return refreshTokenRepository.revokeByPasskeyId(passkeyId);
    }

    /**
     * Attributes one specific session (identified by its raw refresh token) to a passkey.
     * Scoped to a single token hash rather than "all of this user's unlinked sessions":
     * two devices can each hold an unlinked session at the same time, and attributing by
     * user id alone would let whichever device confirms first steal the other's session.
     */
    public Mono<Void> linkSessionToPasskey(String rawRefreshToken, UUID userId, UUID passkeyId) {
        var tokenHash = hashProvider.sha256(rawRefreshToken);
        log.info("DEBUG linkSessionToPasskey: rawToken={} tokenHash={} userId={} -> passkeyId={}",
                rawRefreshToken, tokenHash, userId, passkeyId);
        return refreshTokenRepository.findByTokenHash(tokenHash)
                .filter(token -> token.getUserId().equals(userId))
                .switchIfEmpty(Mono.defer(() -> {
                    log.warn("DEBUG linkSessionToPasskey: token not found or owner mismatch, rawToken={} tokenHash={} userId={}",
                            rawRefreshToken, tokenHash, userId);
                    return Mono.error(new InvalidTokenException());
                }))
                .flatMap(token -> refreshTokenRepository.updatePasskeyIdByTokenHash(tokenHash, passkeyId));
    }
}
