package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.IssuedSession;
import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.model.RefreshToken;
import com.eudistack.ebw.domain.model.SessionSettings;
import com.eudistack.ebw.domain.model.exception.InvalidSessionException;
import com.eudistack.ebw.domain.model.exception.SessionExpiredException;
import com.eudistack.ebw.domain.model.exception.TokenFamilyCompromisedException;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.AuthTokenService;
import com.eudistack.ebw.domain.service.WalletAuthSettingsService;
import com.eudistack.ebw.support.TestPasskeys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link RefreshTokenWorkflow}: every failure becomes {@code invalid_session}. */
@ExtendWith(MockitoExtension.class)
class RefreshTokenWorkflowTest {

    private static final String TENANT = "sandbox";

    @Mock private AuthTokenService authTokenService;
    @Mock private WalletUserRepository userRepository;
    @Mock private WalletAuthSettingsService settingsService;
    @Mock private AuditService auditService;

    private RefreshTokenWorkflow workflow;
    private RefreshToken token;

    @BeforeEach
    void setUp() {
        workflow = new RefreshTokenWorkflow(authTokenService, userRepository, settingsService, auditService);
        token = RefreshToken.create(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), Instant.now(), "h",
                Instant.now().plusSeconds(900));
    }

    private Mono<IssuedSession> refresh(String raw) {
        return workflow.refresh(raw).contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TENANT));
    }

    private void knownToken() {
        when(authTokenService.findRefreshToken("raw")).thenReturn(Mono.just(token));
        when(userRepository.findById(token.getUserId())).thenReturn(Mono.just(TestPasskeys.user("a@b.c")));
        when(settingsService.session()).thenReturn(Mono.just(SessionSettings.defaults()));
    }

    @Test
    void refresh_validCookie_rotatesWithTheTenantLimits() {
        // Arrange
        knownToken();
        var issued = new IssuedSession("access", 300, "new", token.getSessionId(), token.getPasskeyId(),
                Instant.now().plusSeconds(3600));
        when(authTokenService.rotateRefreshToken(eq(token), any(), eq(SessionSettings.defaults()), eq(TENANT)))
                .thenReturn(Mono.just(issued));

        // Act + Assert
        StepVerifier.create(refresh("raw")).expectNext(issued).verifyComplete();
    }

    @Test
    void refresh_unknownCookie_failsWithInvalidSession() {
        // Arrange
        when(authTokenService.findRefreshToken(any())).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(refresh(null)).expectError(InvalidSessionException.class).verify();
    }

    @Test
    void refresh_sessionExpired_auditsAndFailsWithInvalidSession() {
        // Arrange
        knownToken();
        when(authTokenService.rotateRefreshToken(any(), any(), any(), anyString())).thenReturn(Mono.error(
                new SessionExpiredException(token.getSessionId(), token.getUserId(),
                        SessionExpiredException.Reason.IDLE_TIMEOUT)));
        when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(refresh("raw")).expectError(InvalidSessionException.class).verify();
        verify(auditService).record("session", token.getSessionId(), AuthAuditEvents.SESSION_EXPIRED,
                token.getUserId(), Map.of("reason", "idle_timeout"));
    }

    @Test
    void refresh_reusedToken_auditsSessionEndedAndFailsWithInvalidSession() {
        // Arrange
        knownToken();
        when(authTokenService.rotateRefreshToken(any(), any(), any(), anyString())).thenReturn(Mono.error(
                new TokenFamilyCompromisedException(token.getSessionId(), token.getUserId())));
        when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(refresh("raw")).expectError(InvalidSessionException.class).verify();
        verify(auditService).record("session", token.getSessionId(), AuthAuditEvents.SESSION_ENDED,
                token.getUserId(), Map.of("reason", "refresh_token_reuse"));
    }
}
