package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.IssuedSession;
import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.model.RefreshToken;
import com.eudistack.ebw.domain.model.SessionSettings;
import com.eudistack.ebw.domain.model.WalletUser;
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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link SessionOpener}. */
@ExtendWith(MockitoExtension.class)
class SessionOpenerTest {

    private static final String TENANT = "sandbox";

    @Mock private AuthTokenService authTokenService;
    @Mock private WalletAuthSettingsService settingsService;
    @Mock private AuditService auditService;

    private SessionOpener opener;
    private WalletUser user;
    private UUID passkeyId;
    private IssuedSession issued;

    @BeforeEach
    void setUp() {
        opener = new SessionOpener(authTokenService, settingsService, auditService);
        user = TestPasskeys.user("holder@example.com");
        passkeyId = UUID.randomUUID();
        issued = new IssuedSession("access", 300, "refresh", UUID.randomUUID(), passkeyId, Instant.now());
    }

    private Mono<IssuedSession> open(String cookie) {
        return opener.open(user, passkeyId, cookie, "passkey")
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TENANT));
    }

    private void opensSession() {
        when(settingsService.session()).thenReturn(Mono.just(SessionSettings.defaults()));
        when(authTokenService.openSession(user, passkeyId, SessionSettings.defaults(), TENANT)).thenReturn(Mono.just(issued));
        when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());
    }

    @Test
    void open_noCookie_opensSessionAndAuditsAccessGranted() {
        // Arrange
        when(authTokenService.findRefreshToken(null)).thenReturn(Mono.empty());
        opensSession();

        // Act + Assert
        StepVerifier.create(open(null)).expectNext(issued).verifyComplete();
        verify(auditService).record("session", issued.sessionId(), AuthAuditEvents.ACCESS_GRANTED, user.getId(),
                Map.of("passkey_id", passkeyId.toString(), "method", "passkey"));
        verify(authTokenService, never()).endSession(any());
    }

    @Test
    void open_cookieOfAnotherSession_endsThatSessionFirst() {
        // Arrange — FR-21
        var other = RefreshToken.create(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), Instant.now(), "h",
                Instant.now().plusSeconds(60));
        when(authTokenService.findRefreshToken("cookie")).thenReturn(Mono.just(other));
        when(authTokenService.endSession(other.getSessionId())).thenReturn(Mono.just(true));
        opensSession();

        // Act + Assert
        StepVerifier.create(open("cookie")).expectNext(issued).verifyComplete();
        verify(auditService).record("session", other.getSessionId(), AuthAuditEvents.SESSION_ENDED, other.getUserId(),
                Map.of("reason", "replaced_by_new_session"));
    }

    @Test
    void open_withoutTenant_fails() {
        // Arrange
        when(authTokenService.findRefreshToken(null)).thenReturn(Mono.empty());
        when(settingsService.session()).thenReturn(Mono.just(SessionSettings.defaults()));

        // Act + Assert
        StepVerifier.create(opener.open(user, passkeyId, null, "passkey")).expectError(IllegalStateException.class)
                .verify();
        verify(authTokenService, never()).openSession(any(), any(), any(), eq(TENANT));
    }
}
