package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.AuthTokenSettings;
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
import com.eudistack.ebw.support.TestPasskeys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link AuthTokenService}: session opening, rotation, limits and reuse detection. */
@ExtendWith(MockitoExtension.class)
class AuthTokenServiceTest {

    private static final String TENANT = "sandbox";
    private static final SessionSettings SETTINGS = new SessionSettings(Duration.ofMinutes(15), Duration.ofHours(8));

    @Mock private TokenSigner tokenSigner;
    @Mock private HashProvider hashProvider;
    @Mock private SecureRandomGenerator randomGenerator;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private UserPasskeyRepository userPasskeyRepository;

    private AuthTokenService service;
    private WalletUser user;
    private UUID passkeyId;

    @BeforeEach
    void setUp() {
        service = new AuthTokenService(tokenSigner, hashProvider, randomGenerator, refreshTokenRepository,
                userPasskeyRepository, new AuthTokenSettings(Duration.ofMinutes(5), "https://ebw"));
        user = TestPasskeys.user("holder@example.com");
        passkeyId = UUID.randomUUID();
        lenient().when(tokenSigner.sign(any())).thenReturn("access-token");
        lenient().when(hashProvider.sha256(anyString())).thenAnswer(inv -> "sha:" + inv.getArgument(0));
        lenient().when(randomGenerator.generateBytes(anyInt())).thenReturn(new byte[32]);
        lenient().when(randomGenerator.generateUuid()).thenReturn(UUID.randomUUID());
        lenient().when(refreshTokenRepository.insert(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
    }

    private RefreshToken token(Instant sessionStartedAt, Instant expiresAt, boolean revoked) {
        return new RefreshToken(UUID.randomUUID(), user.getId(), passkeyId, UUID.randomUUID(), sessionStartedAt,
                "sha:raw", expiresAt, revoked, Instant.now());
    }

    @Test
    @SuppressWarnings("unchecked")
    void openSession_newSession_signsSessionClaimsAndStoresFirstToken() {
        // Act
        var result = service.openSession(user, passkeyId, SETTINGS, TENANT);

        // Assert
        StepVerifier.create(result)
                .assertNext(session -> {
                    assertThat(session.accessToken()).isEqualTo("access-token");
                    assertThat(session.expiresIn()).isEqualTo(300);
                    assertThat(session.passkeyId()).isEqualTo(passkeyId);
                    assertThat(session.refreshToken()).isNotBlank();
                })
                .verifyComplete();
        var claims = ArgumentCaptor.forClass(Map.class);
        verify(tokenSigner).sign(claims.capture());
        assertThat(claims.getValue()).containsKeys("sub", "email", "tenant", "sid", "pkid", "iss", "iat", "exp");
        assertThat(claims.getValue()).containsEntry("tenant", TENANT);
        assertThat(claims.getValue()).containsEntry("pkid", passkeyId.toString());
        var stored = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).insert(stored.capture());
        assertThat(stored.getValue().getPasskeyId()).isEqualTo(passkeyId);
        assertThat(stored.getValue().getExpiresAt())
                .isCloseTo(Instant.now().plus(Duration.ofMinutes(15)), org.assertj.core.api.Assertions.within(5, ChronoUnit.SECONDS));
    }

    @Test
    void rotateRefreshToken_activeToken_rotatesWithinTheSameSession() {
        // Arrange
        var started = Instant.now().minus(Duration.ofHours(1));
        var existing = token(started, Instant.now().plusSeconds(600), false);
        when(refreshTokenRepository.revokeIfActive(existing.getId())).thenReturn(Mono.just(true));
        when(userPasskeyRepository.touchLastUsed(passkeyId)).thenReturn(Mono.empty());

        // Act
        var result = service.rotateRefreshToken(existing, user, SETTINGS, TENANT);

        // Assert
        StepVerifier.create(result)
                .assertNext(session -> {
                    assertThat(session.sessionId()).isEqualTo(existing.getSessionId());
                    assertThat(session.sessionExpiresAt()).isEqualTo(started.plus(Duration.ofHours(8)));
                })
                .verifyComplete();
        var stored = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).insert(stored.capture());
        assertThat(stored.getValue().getSessionId()).isEqualTo(existing.getSessionId());
        assertThat(stored.getValue().getSessionStartedAt()).isEqualTo(started);
    }

    @Test
    void rotateRefreshToken_nearMaxDuration_capsTheNewTokenAtTheSessionEnd() {
        // Arrange
        var started = Instant.now().minus(Duration.ofHours(8)).plusSeconds(60);
        var existing = token(started, Instant.now().plusSeconds(60), false);
        when(refreshTokenRepository.revokeIfActive(existing.getId())).thenReturn(Mono.just(true));
        when(userPasskeyRepository.touchLastUsed(passkeyId)).thenReturn(Mono.empty());

        // Act
        StepVerifier.create(service.rotateRefreshToken(existing, user, SETTINGS, TENANT)).expectNextCount(1)
                .verifyComplete();

        // Assert
        var stored = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).insert(stored.capture());
        assertThat(stored.getValue().getExpiresAt()).isEqualTo(started.plus(Duration.ofHours(8)));
    }

    @Test
    void rotateRefreshToken_idleExpired_endsSessionWithIdleReason() {
        // Arrange
        var existing = token(Instant.now().minus(Duration.ofHours(1)), Instant.now().minusSeconds(1), false);
        when(refreshTokenRepository.revokeBySessionId(existing.getSessionId())).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(service.rotateRefreshToken(existing, user, SETTINGS, TENANT))
                .expectErrorSatisfies(e -> assertThat(e).isInstanceOf(SessionExpiredException.class)
                        .extracting("reason").isEqualTo(SessionExpiredException.Reason.IDLE_TIMEOUT))
                .verify();
        verify(refreshTokenRepository, never()).insert(any());
    }

    @Test
    void rotateRefreshToken_pastMaxDuration_endsSessionEvenWithActivity() {
        // Arrange
        var existing = token(Instant.now().minus(Duration.ofHours(9)), Instant.now().plusSeconds(600), false);
        when(refreshTokenRepository.revokeBySessionId(existing.getSessionId())).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(service.rotateRefreshToken(existing, user, SETTINGS, TENANT))
                .expectErrorSatisfies(e -> assertThat(e).isInstanceOf(SessionExpiredException.class)
                        .extracting("reason").isEqualTo(SessionExpiredException.Reason.MAX_DURATION))
                .verify();
    }

    @Test
    void rotateRefreshToken_revokedToken_endsTheWholeSession() {
        // Arrange
        var existing = token(Instant.now(), Instant.now().plusSeconds(600), true);
        when(refreshTokenRepository.hasActiveToken(existing.getSessionId())).thenReturn(Mono.just(true));
        when(refreshTokenRepository.revokeBySessionId(existing.getSessionId())).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(service.rotateRefreshToken(existing, user, SETTINGS, TENANT))
                .expectError(TokenFamilyCompromisedException.class).verify();
        verify(refreshTokenRepository).revokeBySessionId(existing.getSessionId());
    }

    @Test
    void rotateRefreshToken_revokedTokenOfAnEndedSession_isInvalidSessionWithoutReuseAlarm() {
        // Arrange
        var existing = token(Instant.now(), Instant.now().plusSeconds(600), true);
        when(refreshTokenRepository.hasActiveToken(existing.getSessionId())).thenReturn(Mono.just(false));

        // Act + Assert
        StepVerifier.create(service.rotateRefreshToken(existing, user, SETTINGS, TENANT))
                .expectError(InvalidSessionException.class).verify();
        verify(refreshTokenRepository, never()).revokeBySessionId(any());
    }

    @Test
    void rotateRefreshToken_concurrentRotationLost_treatedAsReuse() {
        // Arrange
        var existing = token(Instant.now(), Instant.now().plusSeconds(600), false);
        when(refreshTokenRepository.revokeIfActive(existing.getId())).thenReturn(Mono.just(false));
        when(refreshTokenRepository.hasActiveToken(existing.getSessionId())).thenReturn(Mono.just(true));
        when(refreshTokenRepository.revokeBySessionId(existing.getSessionId())).thenReturn(Mono.empty());
        when(refreshTokenRepository.deleteById(any())).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(service.rotateRefreshToken(existing, user, SETTINGS, TENANT))
                .expectError(TokenFamilyCompromisedException.class).verify();
        // The token stored for the lost renewal is removed again.
        var stored = org.mockito.ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).insert(stored.capture());
        verify(refreshTokenRepository).deleteById(stored.getValue().getId());
    }

    @Test
    void rotateRefreshToken_tokenOfAnotherAccount_failsWithInvalidSession() {
        // Arrange
        var existing = token(Instant.now(), Instant.now().plusSeconds(600), false);
        var other = TestPasskeys.user("other@example.com");

        // Act + Assert
        StepVerifier.create(service.rotateRefreshToken(existing, other, SETTINGS, TENANT))
                .expectError(InvalidSessionException.class).verify();
    }

    @Test
    void findRefreshToken_blankValue_completesEmpty() {
        StepVerifier.create(service.findRefreshToken(" ")).verifyComplete();
        verify(refreshTokenRepository, never()).findByTokenHash(any());
    }

    @Test
    void endOtherSessions_delegatesKeepingTheCurrentSession() {
        // Arrange
        var current = UUID.randomUUID();
        when(refreshTokenRepository.revokeByUserIdExceptSession(user.getId(), current)).thenReturn(Mono.just(2L));

        // Act + Assert
        StepVerifier.create(service.endOtherSessions(user.getId(), current)).expectNext(2L).verifyComplete();
    }
}
