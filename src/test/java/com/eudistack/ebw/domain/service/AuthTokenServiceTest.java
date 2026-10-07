package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.RefreshToken;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.model.exception.InvalidTokenException;
import com.eudistack.ebw.domain.model.exception.TokenFamilyCompromisedException;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
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
    private UserPasskeyRepository userPasskeyRepository;
    private AuthTokenService authTokenService;

    private WalletUser testUser;

    @BeforeEach
    void setUp() {
        tokenSigner = mock(TokenSigner.class);
        hashProvider = mock(HashProvider.class);
        randomGenerator = mock(SecureRandomGenerator.class);
        refreshTokenRepository = mock(RefreshTokenRepository.class);
        userPasskeyRepository = mock(UserPasskeyRepository.class);
        when(userPasskeyRepository.touchLastUsed(any())).thenReturn(Mono.empty());
        authTokenService = new AuthTokenService(tokenSigner, hashProvider, randomGenerator,
                refreshTokenRepository, userPasskeyRepository, Duration.ofMinutes(15), Duration.ofDays(7), "eudistack-ebw");

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
        verify(userPasskeyRepository, never()).touchLastUsed(any());
    }

    @Test
    void rotateRefreshToken_tokenLinkedToPasskey_touchesPasskeyLastUsed() {
        // Arrange: #1061961 — a refresh is device activity ("Última actividad")
        var rawToken = "device-refresh-token";
        var passkeyId = UUID.randomUUID();
        var existingToken = RefreshToken.create(testUser.getId(), passkeyId, "sha256-hash",
                Instant.now().plusSeconds(3600));
        when(hashProvider.sha256(anyString())).thenReturn("sha256-hash");
        when(refreshTokenRepository.findByTokenHash("sha256-hash")).thenReturn(Mono.just(existingToken));
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        when(tokenSigner.sign(anyMap())).thenReturn("new-jwt");
        when(randomGenerator.generateUuid()).thenReturn(UUID.randomUUID());

        // Act
        var result = authTokenService.rotateRefreshToken(rawToken, testUser);

        // Assert
        StepVerifier.create(result)
                .assertNext(pair -> assertThat(pair.accessToken()).isEqualTo("new-jwt"))
                .verifyComplete();
        verify(userPasskeyRepository).touchLastUsed(passkeyId);
    }

    @Test
    void rotateRefreshToken_touchFails_stillIssuesNewPair() {
        // Arrange: activity bookkeeping must never break the session refresh
        var rawToken = "device-refresh-token";
        var passkeyId = UUID.randomUUID();
        var existingToken = RefreshToken.create(testUser.getId(), passkeyId, "sha256-hash",
                Instant.now().plusSeconds(3600));
        when(hashProvider.sha256(anyString())).thenReturn("sha256-hash");
        when(refreshTokenRepository.findByTokenHash("sha256-hash")).thenReturn(Mono.just(existingToken));
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        when(tokenSigner.sign(anyMap())).thenReturn("new-jwt");
        when(randomGenerator.generateUuid()).thenReturn(UUID.randomUUID());
        when(userPasskeyRepository.touchLastUsed(passkeyId))
                .thenReturn(Mono.error(new RuntimeException("db down")));

        // Act
        var result = authTokenService.rotateRefreshToken(rawToken, testUser);

        // Assert
        StepVerifier.create(result)
                .assertNext(pair -> assertThat(pair.accessToken()).isEqualTo("new-jwt"))
                .verifyComplete();
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
    void rotateRefreshToken_revokedTokenWithPasskey_revokesOnlyThatDevice() {
        // Arrange
        var rawToken = "reused-token";
        var passkeyId = UUID.randomUUID();
        var revokedToken = RefreshToken.create(testUser.getId(), passkeyId, "sha256-hash",
                Instant.now().plusSeconds(3600));
        revokedToken.revoke();
        when(hashProvider.sha256(rawToken)).thenReturn("sha256-hash");
        when(refreshTokenRepository.findByTokenHash("sha256-hash")).thenReturn(Mono.just(revokedToken));
        when(refreshTokenRepository.revokeByPasskeyId(passkeyId)).thenReturn(Mono.empty());

        // Act
        var result = authTokenService.rotateRefreshToken(rawToken, testUser);

        // Assert
        StepVerifier.create(result)
                .expectError(TokenFamilyCompromisedException.class)
                .verify();
        verify(refreshTokenRepository).revokeByPasskeyId(passkeyId);
        verify(refreshTokenRepository, never()).revokeByUserId(any());
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

    @Test
    void linkSessionToPasskey_ownedByCaller_updatesPasskeyIdByTokenHash() {
        // Arrange
        var rawToken = "session-token";
        var passkeyId = UUID.randomUUID();
        var existingToken = RefreshToken.create(testUser.getId(), null, "sha256-hash",
                Instant.now().plusSeconds(3600));
        when(hashProvider.sha256(rawToken)).thenReturn("sha256-hash");
        when(refreshTokenRepository.findByTokenHash("sha256-hash")).thenReturn(Mono.just(existingToken));
        when(refreshTokenRepository.updatePasskeyIdByTokenHash("sha256-hash", passkeyId)).thenReturn(Mono.empty());

        // Act
        var result = authTokenService.linkSessionToPasskey(rawToken, testUser.getId(), passkeyId);

        // Assert
        StepVerifier.create(result)
                .verifyComplete();
        verify(refreshTokenRepository).updatePasskeyIdByTokenHash("sha256-hash", passkeyId);
        verify(userPasskeyRepository).touchLastUsed(passkeyId);
    }

    @Test
    void linkSessionToPasskey_touchFails_stillCompletes() {
        // Arrange: activity bookkeeping must never break the session attribution
        var rawToken = "session-token";
        var passkeyId = UUID.randomUUID();
        var existingToken = RefreshToken.create(testUser.getId(), null, "sha256-hash",
                Instant.now().plusSeconds(3600));
        when(hashProvider.sha256(rawToken)).thenReturn("sha256-hash");
        when(refreshTokenRepository.findByTokenHash("sha256-hash")).thenReturn(Mono.just(existingToken));
        when(refreshTokenRepository.updatePasskeyIdByTokenHash("sha256-hash", passkeyId)).thenReturn(Mono.empty());
        when(userPasskeyRepository.touchLastUsed(passkeyId))
                .thenReturn(Mono.error(new RuntimeException("db down")));

        // Act
        var result = authTokenService.linkSessionToPasskey(rawToken, testUser.getId(), passkeyId);

        // Assert
        StepVerifier.create(result)
                .verifyComplete();
        verify(refreshTokenRepository).updatePasskeyIdByTokenHash("sha256-hash", passkeyId);
        verify(userPasskeyRepository).touchLastUsed(passkeyId);
    }

    @Test
    void linkSessionToPasskey_tokenNotFound_throwsInvalidTokenException() {
        // Arrange
        var rawToken = "unknown-token";
        var passkeyId = UUID.randomUUID();
        when(hashProvider.sha256(rawToken)).thenReturn("sha256-hash");
        when(refreshTokenRepository.findByTokenHash("sha256-hash")).thenReturn(Mono.empty());

        // Act
        var result = authTokenService.linkSessionToPasskey(rawToken, testUser.getId(), passkeyId);

        // Assert
        StepVerifier.create(result)
                .expectError(InvalidTokenException.class)
                .verify();
        verify(refreshTokenRepository, never()).updatePasskeyIdByTokenHash(any(), any());
        verify(userPasskeyRepository, never()).touchLastUsed(any());
    }

    @Test
    void linkSessionToPasskey_tokenBelongsToAnotherUser_throwsInvalidTokenException() {
        // Arrange: the token is real, but it was issued to a different account — This is
        // the guard against attributing someone else's session to your own passkey.
        var rawToken = "someone-elses-token";
        var passkeyId = UUID.randomUUID();
        var otherUsersToken = RefreshToken.create(UUID.randomUUID(), null, "sha256-hash",
                Instant.now().plusSeconds(3600));
        when(hashProvider.sha256(rawToken)).thenReturn("sha256-hash");
        when(refreshTokenRepository.findByTokenHash("sha256-hash")).thenReturn(Mono.just(otherUsersToken));

        // Act
        var result = authTokenService.linkSessionToPasskey(rawToken, testUser.getId(), passkeyId);

        // Assert
        StepVerifier.create(result)
                .expectError(InvalidTokenException.class)
                .verify();
        verify(refreshTokenRepository, never()).updatePasskeyIdByTokenHash(any(), any());
        verify(userPasskeyRepository, never()).touchLastUsed(any());
    }
}
