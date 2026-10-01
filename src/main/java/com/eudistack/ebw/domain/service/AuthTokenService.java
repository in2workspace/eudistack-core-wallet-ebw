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
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public class AuthTokenService {

    private final TokenSigner tokenSigner;
    private final HashProvider hashProvider;
    private final SecureRandomGenerator randomGenerator;
    private final RefreshTokenRepository refreshTokenRepository;
    private final SessionRevocationChecker sessionRevocationChecker;
    private final Duration accessTokenTtl;
    private final Duration refreshTokenTtl;
    private final String issuer;

    public AuthTokenService(TokenSigner tokenSigner,
                            HashProvider hashProvider,
                            SecureRandomGenerator randomGenerator,
                            RefreshTokenRepository refreshTokenRepository,
                            SessionRevocationChecker sessionRevocationChecker,
                            Duration accessTokenTtl,
                            Duration refreshTokenTtl,
                            String issuer) {
        this.tokenSigner = tokenSigner;
        this.hashProvider = hashProvider;
        this.randomGenerator = randomGenerator;
        this.refreshTokenRepository = refreshTokenRepository;
        this.sessionRevocationChecker = sessionRevocationChecker;
        this.accessTokenTtl = accessTokenTtl;
        this.refreshTokenTtl = refreshTokenTtl;
        this.issuer = issuer;
    }

    public Mono<AuthTokenPair> issueTokenPair(WalletUser user, UUID passkeyId) {
        var now = Instant.now();
        var exp = now.plus(accessTokenTtl);

        var rawRefreshToken = randomGenerator.generateUuid().toString();
        var tokenHash = hashProvider.sha256(rawRefreshToken);
        var refreshToken = RefreshToken.create(
                user.getId(), passkeyId, tokenHash, now.plus(refreshTokenTtl));

        // "sid" ties the access token to the refresh-token row that spawned it, so
        // JwtAuthenticationWebFilter can reject it the moment that row is revoked
        // instead of only at its own `exp` — see SessionRevocationChecker.
        var claims = Map.<String, Object>of(
                "sub", user.getId().toString(),
                "email", user.getEmail(),
                "iss", issuer,
                "iat", now.getEpochSecond(),
                "exp", exp.getEpochSecond(),
                "sid", refreshToken.getId().toString()
        );

        var accessToken = tokenSigner.sign(claims);

        return refreshTokenRepository.save(refreshToken)
                .thenReturn(new AuthTokenPair(accessToken, rawRefreshToken, accessTokenTtl.toSeconds()));
    }

    public Map<String, Object> validateAccessToken(String token) {
        return tokenSigner.verify(token);
    }

    public Mono<AuthTokenPair> rotateRefreshToken(String rawToken, WalletUser user) {
        var tokenHash = hashProvider.sha256(rawToken);
        return refreshTokenRepository.findByTokenHash(tokenHash)
                .switchIfEmpty(Mono.error(new InvalidTokenException()))
                .flatMap(existing -> {
                    if (existing.isRevoked()) {
                        // A non-null passkeyId scopes the compromise response to every
                        // session of that one device (defense in depth: if one of its
                        // tokens was reused, treat the whole device as suspect). A null
                        // passkeyId is NOT proof this token was never attributed to any
                        // device — deleting a passkey nulls it via refresh_token's
                        // ON DELETE SET NULL — so revoking "by user" here must stay
                        // scoped to still-unattributed sessions only (revokeOrphanByUserId),
                        // never every session for the user: that let a deleted device's
                        // own retried refresh wipe out every other, properly-attributed
                        // device's session too.
                        var revoke = existing.getPasskeyId() != null
                                ? refreshTokenRepository.revokeByPasskeyId(existing.getPasskeyId())
                                : refreshTokenRepository.revokeOrphanByUserId(existing.getUserId());
                        return revoke.doOnSuccess(v -> sessionRevocationChecker.invalidateAll())
                                .then(Mono.error(new TokenFamilyCompromisedException()));
                    }
                    if (existing.isExpired()) {
                        return Mono.error(new InvalidTokenException());
                    }
                    existing.revoke();
                    return refreshTokenRepository.save(existing)
                            .then(issueTokenPair(user, existing.getPasskeyId()));
                });
    }

    /**
     * Per-device logout: finds the token by hash, revokes only that one session.
     * Returns the userId for audit purposes, or empty if token not found (idempotent) —
     * other devices' sessions for the same user are left untouched.
     */
    public Mono<UUID> revokeRefreshToken(String rawToken) {
        var tokenHash = hashProvider.sha256(rawToken);
        return refreshTokenRepository.findByTokenHash(tokenHash)
                .flatMap(token -> {
                    var userId = token.getUserId();
                    token.revoke();
                    return refreshTokenRepository.save(token).thenReturn(userId);
                })
                .doOnSuccess(userId -> sessionRevocationChecker.invalidateAll());
    }

    public Mono<Void> revokeAllByUser(UUID userId) {
        return refreshTokenRepository.revokeByUserId(userId)
                .doOnSuccess(v -> sessionRevocationChecker.invalidateAll());
    }

    public Mono<Void> revokeAllByPasskey(UUID passkeyId) {
        return refreshTokenRepository.revokeByPasskeyId(passkeyId)
                .doOnSuccess(v -> sessionRevocationChecker.invalidateAll());
    }

    /**
     * Attributes one specific session (identified by its raw refresh token) to a passkey.
     * Scoped to a single token hash rather than "all of this user's unlinked sessions":
     * two devices can each hold an unlinked session at the same time, and attributing by
     * user id alone would let whichever device confirms first steal the other's session.
     */
    public Mono<Void> linkSessionToPasskey(String rawRefreshToken, UUID userId, UUID passkeyId) {
        var tokenHash = hashProvider.sha256(rawRefreshToken);
        return refreshTokenRepository.findByTokenHash(tokenHash)
                .filter(token -> token.getUserId().equals(userId))
                .switchIfEmpty(Mono.error(new InvalidTokenException()))
                .flatMap(token -> refreshTokenRepository.updatePasskeyIdByTokenHash(tokenHash, passkeyId));
    }
}
