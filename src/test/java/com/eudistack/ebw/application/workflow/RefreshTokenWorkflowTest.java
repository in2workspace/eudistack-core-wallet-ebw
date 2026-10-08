package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.AuthTokenPair;
import com.eudistack.ebw.domain.model.RefreshToken;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.model.exception.InvalidTokenException;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.service.AuthTokenService;
import com.eudistack.ebw.domain.spi.HashProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link RefreshTokenWorkflow} — resolves the token owner before delegating the rotation.
 */
@ExtendWith(MockitoExtension.class)
class RefreshTokenWorkflowTest {

    private static final String RAW_TOKEN = "raw-refresh-token";
    private static final String TOKEN_HASH = "token-hash";

    @Mock private AuthTokenService authTokenService;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private WalletUserRepository userRepository;
    @Mock private HashProvider hashProvider;

    private RefreshTokenWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new RefreshTokenWorkflow(authTokenService, refreshTokenRepository, userRepository, hashProvider);
        when(hashProvider.sha256(RAW_TOKEN)).thenReturn(TOKEN_HASH);
    }

    @Test
    void refreshToken_knownTokenAndUser_rotatesTheTokenPair() {
        // Arrange
        var user = WalletUser.create("holder@example.com");
        var stored = RefreshToken.create(user.getId(), null, TOKEN_HASH, Instant.now().plusSeconds(60));
        var pair = new AuthTokenPair("access", "new-refresh", 900);
        when(refreshTokenRepository.findByTokenHash(TOKEN_HASH)).thenReturn(Mono.just(stored));
        when(userRepository.findById(user.getId())).thenReturn(Mono.just(user));
        when(authTokenService.rotateRefreshToken(RAW_TOKEN, user)).thenReturn(Mono.just(pair));

        // Act
        var result = workflow.refreshToken(RAW_TOKEN);

        // Assert
        StepVerifier.create(result).expectNext(pair).verifyComplete();
    }

    @Test
    void refreshToken_unknownToken_failsWithInvalidToken() {
        // Arrange
        when(refreshTokenRepository.findByTokenHash(TOKEN_HASH)).thenReturn(Mono.empty());

        // Act
        var result = workflow.refreshToken(RAW_TOKEN);

        // Assert
        StepVerifier.create(result).expectError(InvalidTokenException.class).verify();
        verify(authTokenService, never()).rotateRefreshToken(any(), any());
    }

    @Test
    void refreshToken_ownerNoLongerExists_failsWithInvalidToken() {
        // Arrange
        var userId = UUID.randomUUID();
        var stored = RefreshToken.create(userId, null, TOKEN_HASH, Instant.now().plusSeconds(60));
        when(refreshTokenRepository.findByTokenHash(TOKEN_HASH)).thenReturn(Mono.just(stored));
        when(userRepository.findById(userId)).thenReturn(Mono.empty());

        // Act
        var result = workflow.refreshToken(RAW_TOKEN);

        // Assert
        StepVerifier.create(result).expectError(InvalidTokenException.class).verify();
        verify(authTokenService, never()).rotateRefreshToken(any(), any());
    }
}
