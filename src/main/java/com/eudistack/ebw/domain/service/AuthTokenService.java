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
                        // Token family compromise detected
                        return refreshTokenRepository.revokeByUserId(existing.getUserId())
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
                    return refreshTokenRepository.revokeByUserId(userId)
                            .thenReturn(userId);
                });
    }

    public Mono<Void> revokeAllByUser(UUID userId) {
        return refreshTokenRepository.revokeByUserId(userId);
    }

    public Mono<Void> revokeAllByPasskey(UUID passkeyId) {
        return refreshTokenRepository.revokeByPasskeyId(passkeyId);
    }
}
