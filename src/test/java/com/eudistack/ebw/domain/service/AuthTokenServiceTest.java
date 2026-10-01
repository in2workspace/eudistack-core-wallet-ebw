package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.RefreshToken;
import com.eudistack.ebw.domain.model.TokenIssuanceSettings;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.model.exception.InvalidTokenException;
import com.eudistack.ebw.domain.model.exception.TokenFamilyCompromisedException;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.eudistack.ebw.domain.spi.HashProvider;
import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
import com.eudistack.ebw.domain.spi.TokenSigner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
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
    private SessionRevocationChecker sessionRevocationChecker;
    private AuthTokenService authTokenService;

    private WalletUser testUser;

    @BeforeEach
    void setUp() {
        tokenSigner = mock(TokenSigner.class);
        hashProvider = mock(HashProvider.class);
        randomGenerator = mock(SecureRandomGenerator.class);
        refreshTokenRepository = mock(RefreshTokenRepository.class);
        sessionRevocationChecker = mock(SessionRevocationChecker.class);
        var tokenIssuanceSettings = new TokenIssuanceSettings(
                Duration.ofMinutes(15), Duration.ofDays(7), "eudistack-ebw");
        authTokenService = new AuthTokenService(tokenSigner, hashProvider, randomGenerator,
                refreshTokenRepository, sessionRevocationChecker, tokenIssuanceSettings);

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
    void issueTokenPair_validUser_signsAccessTokenWithSidClaimMatchingRefreshTokenId() {
        // Arrange
        when(tokenSigner.sign(anyMap())).thenReturn("jwt-access-token");
        when(randomGenerator.generateUuid()).thenReturn(UUID.randomUUID());
        when(hashProvider.sha256(anyString())).thenReturn("sha256-hash");
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> claimsCaptor = ArgumentCaptor.forClass(Map.class);
        ArgumentCaptor<RefreshToken> tokenCaptor = ArgumentCaptor.forClass(RefreshToken.class);

        // Act
        StepVerifier.create(authTokenService.issueTokenPair(testUser, null))
                .expectNextCount(1)
                .verifyComplete();

        // Assert — JwtAuthenticationWebFilter relies on "sid" matching the persisted
        // refresh-token row's id to reject the access token once that row is revoked.
        verify(tokenSigner).sign(claimsCaptor.capture());
        verify(refreshTokenRepository).save(tokenCaptor.capture());
        assertThat(claimsCaptor.getValue()).containsEntry("sid", tokenCaptor.getValue().getId().toString());
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
    void rotateRefreshToken_revokedTokenWithoutPasskey_revokesOnlyOrphanSessionsNotEveryDevice() {
        // Arrange — a null passkeyId here is NOT proof this token was never attributed
        // to a device: deleting a passkey nulls it via ON DELETE SET NULL on
        // refresh_token.passkey_id. Falling back to the unscoped revokeByUserId used to
        // let a deleted device's own retried refresh wipe out every other, properly
        // attributed device's session too — see AuthTokenService.rotateRefreshToken.
        var rawToken = "reused-token";
        var revokedToken = RefreshToken.create(testUser.getId(), null, "sha256-hash",
                Instant.now().plusSeconds(3600));
        revokedToken.revoke();
        when(hashProvider.sha256(rawToken)).thenReturn("sha256-hash");
        when(refreshTokenRepository.findByTokenHash("sha256-hash")).thenReturn(Mono.just(revokedToken));
        when(refreshTokenRepository.revokeOrphanByUserId(testUser.getId())).thenReturn(Mono.empty());

        // Act
        var result = authTokenService.rotateRefreshToken(rawToken, testUser);

        // Assert — only still-unattributed sessions for the user are revoked; devices
        // with a real passkey are never touched by this branch.
        StepVerifier.create(result)
                .expectError(TokenFamilyCompromisedException.class)
                .verify();
        verify(refreshTokenRepository).revokeOrphanByUserId(testUser.getId());
        verify(refreshTokenRepository, never()).revokeByUserId(any());
        verify(refreshTokenRepository, never()).revokeByPasskeyId(any());
        verify(sessionRevocationChecker).invalidateAll();
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
        verify(sessionRevocationChecker).invalidateAll();
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
    void revokeRefreshToken_existingToken_revokesOnlyThatSessionAndReturnsUserId() {
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
                .expectNext(testUser.getId())
                .verifyComplete();
        assertThat(token.isRevoked()).isTrue();
        verify(refreshTokenRepository, never()).revokeByUserId(any());
        verify(refreshTokenRepository, never()).revokeByPasskeyId(any());
        verify(sessionRevocationChecker).invalidateAll();
    }

    @Test
    void revokeRefreshToken_notFound_completesEmpty() {
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
    void revokeAllByPasskey_delegatesToRepositoryAndInvalidatesSessionCache() {
        // Arrange
        var passkeyId = UUID.randomUUID();
        when(refreshTokenRepository.revokeByPasskeyId(passkeyId)).thenReturn(Mono.empty());

        // Act
        StepVerifier.create(authTokenService.revokeAllByPasskey(passkeyId)).verifyComplete();

        // Assert
        verify(refreshTokenRepository).revokeByPasskeyId(passkeyId);
        verify(sessionRevocationChecker).invalidateAll();
    }

    @Test
    void revokeAllByUser_delegatesToRepositoryAndInvalidatesSessionCache() {
        // Arrange
        when(refreshTokenRepository.revokeByUserId(testUser.getId())).thenReturn(Mono.empty());

        // Act
        StepVerifier.create(authTokenService.revokeAllByUser(testUser.getId())).verifyComplete();

        // Assert
        verify(refreshTokenRepository).revokeByUserId(testUser.getId());
        verify(sessionRevocationChecker).invalidateAll();
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
    }
}
