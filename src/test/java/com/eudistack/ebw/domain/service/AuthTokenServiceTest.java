package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.RefreshToken;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.model.exception.InvalidTokenException;
import com.eudistack.ebw.domain.model.exception.TokenFamilyCompromisedException;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.eudistack.ebw.domain.spi.HashProvider;
import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
import com.eudistack.ebw.domain.spi.TokenSigner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.*;

class AuthTokenServiceTest {

    private TokenSigner tokenSigner;
    private HashProvider hashProvider;
    private SecureRandomGenerator randomGenerator;
    private RefreshTokenRepository refreshTokenRepository;
    private AuthTokenService authTokenService;

    private WalletUser testUser;

    @BeforeEach
    void setUp() {
        tokenSigner = mock(TokenSigner.class);
        hashProvider = mock(HashProvider.class);
        randomGenerator = mock(SecureRandomGenerator.class);
        refreshTokenRepository = mock(RefreshTokenRepository.class);
        authTokenService = new AuthTokenService(tokenSigner, hashProvider, randomGenerator,
                refreshTokenRepository, Duration.ofMinutes(15), Duration.ofDays(7), "eudistack-ebw");

        testUser = WalletUser.create("user@example.com");
    }

    @Test
    void issueTokenPair_validUser_returnsAccessAndRefreshToken() {
        // Arrange
        var refreshUuid = UUID.randomUUID();
        when(tokenSigner.sign(anyMap())).thenReturn("jwt-access-token");
        when(randomGenerator.generateUuid()).thenReturn(refreshUuid);
        when(hashProvider.sha256(refreshUuid.toString())).thenReturn("sha256-hash");
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Act
        var result = authTokenService.issueTokenPair(testUser, null);

        // Assert
        StepVerifier.create(result)
                .assertNext(pair -> {
                    assertThat(pair.accessToken()).isEqualTo("jwt-access-token");
                    assertThat(pair.refreshToken()).isEqualTo(refreshUuid.toString());
                    assertThat(pair.expiresIn()).isEqualTo(900);
                })
                .verifyComplete();
    }

    @Test
    void rotateRefreshToken_validToken_revokesOldAndIssuesNew() {
        // Arrange
        var rawToken = "old-refresh-token";
        var newRefreshUuid = UUID.randomUUID();
        var existingToken = RefreshToken.create(testUser.getId(), null, "sha256-hash",
                Instant.now().plusSeconds(3600));
        when(hashProvider.sha256(anyString())).thenAnswer(inv -> {
            String arg = inv.getArgument(0);
            if (rawToken.equals(arg)) return "sha256-hash";
            return "new-sha256";
        });
        when(refreshTokenRepository.findByTokenHash("sha256-hash")).thenReturn(Mono.just(existingToken));
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        when(tokenSigner.sign(anyMap())).thenReturn("new-jwt");
        when(randomGenerator.generateUuid()).thenReturn(newRefreshUuid);

        // Act
        var result = authTokenService.rotateRefreshToken(rawToken, testUser);

        // Assert
        StepVerifier.create(result)
                .assertNext(pair -> {
                    assertThat(pair.accessToken()).isEqualTo("new-jwt");
                    assertThat(pair.expiresIn()).isEqualTo(900);
                })
                .verifyComplete();
        assertThat(existingToken.isRevoked()).isTrue();
    }

    @Test
    void rotateRefreshToken_revokedToken_compromiseDetected() {
        // Arrange
        var rawToken = "reused-token";
        var revokedToken = RefreshToken.create(testUser.getId(), null, "sha256-hash",
                Instant.now().plusSeconds(3600));
        revokedToken.revoke();
        when(hashProvider.sha256(rawToken)).thenReturn("sha256-hash");
        when(refreshTokenRepository.findByTokenHash("sha256-hash")).thenReturn(Mono.just(revokedToken));
        when(refreshTokenRepository.revokeByUserId(testUser.getId())).thenReturn(Mono.empty());

        // Act
        var result = authTokenService.rotateRefreshToken(rawToken, testUser);

        // Assert
        StepVerifier.create(result)
                .expectError(TokenFamilyCompromisedException.class)
                .verify();
        verify(refreshTokenRepository).revokeByUserId(testUser.getId());
    }

    @Test
    void rotateRefreshToken_expiredToken_throwsInvalidTokenException() {
        // Arrange
        var rawToken = "expired-token";
        var expiredToken = RefreshToken.create(testUser.getId(), null, "sha256-hash",
                Instant.now().minusSeconds(1));
        when(hashProvider.sha256(rawToken)).thenReturn("sha256-hash");
        when(refreshTokenRepository.findByTokenHash("sha256-hash")).thenReturn(Mono.just(expiredToken));

        // Act
        var result = authTokenService.rotateRefreshToken(rawToken, testUser);

        // Assert
        StepVerifier.create(result)
                .expectError(InvalidTokenException.class)
                .verify();
    }

    @Test
    void rotateRefreshToken_notFound_throwsInvalidTokenException() {
        // Arrange
        var rawToken = "unknown-token";
        when(hashProvider.sha256(rawToken)).thenReturn("sha256-hash");
        when(refreshTokenRepository.findByTokenHash("sha256-hash")).thenReturn(Mono.empty());

        // Act
        var result = authTokenService.rotateRefreshToken(rawToken, testUser);

        // Assert
        StepVerifier.create(result)
                .expectError(InvalidTokenException.class)
                .verify();
    }

    @Test
    void revokeRefreshToken_existingToken_revokesSuccessfully() {
        // Arrange
        var rawToken = "token-to-revoke";
        var token = RefreshToken.create(testUser.getId(), null, "sha256-hash",
                Instant.now().plusSeconds(3600));
        when(hashProvider.sha256(rawToken)).thenReturn("sha256-hash");
        when(refreshTokenRepository.findByTokenHash("sha256-hash")).thenReturn(Mono.just(token));
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Act
        var result = authTokenService.revokeRefreshToken(rawToken);

        // Assert
        StepVerifier.create(result)
                .verifyComplete();
        assertThat(token.isRevoked()).isTrue();
    }

    @Test
    void revokeRefreshToken_notFound_completesSuccessfully() {
        // Arrange
        var rawToken = "unknown-token";
        when(hashProvider.sha256(rawToken)).thenReturn("sha256-hash");
        when(refreshTokenRepository.findByTokenHash("sha256-hash")).thenReturn(Mono.empty());

        // Act
        var result = authTokenService.revokeRefreshToken(rawToken);

        // Assert
        StepVerifier.create(result)
                .verifyComplete();
    }
}
