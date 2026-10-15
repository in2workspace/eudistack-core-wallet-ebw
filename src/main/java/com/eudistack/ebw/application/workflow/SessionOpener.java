package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.IssuedSession;
import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.AuthTokenService;
import com.eudistack.ebw.domain.service.WalletAuthSettingsService;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

/**
 * Opens a session after a verified passkey (registration or sign-in). Any session of the
 * refresh cookie the request carries is ended first: one session per container (FR-21).
 */
@Service
public class SessionOpener {

    private final AuthTokenService authTokenService;
    private final WalletAuthSettingsService settingsService;
    private final AuditService auditService;

    public SessionOpener(AuthTokenService authTokenService, WalletAuthSettingsService settingsService,
                         AuditService auditService) {
        this.authTokenService = authTokenService;
        this.settingsService = settingsService;
        this.auditService = auditService;
    }

    public Mono<IssuedSession> open(WalletUser user, UUID passkeyId, String replacedRefreshToken, String method) {
        return endReplacedSession(replacedRefreshToken)
                .then(Mono.zip(settingsService.session(), currentTenant()))
                .flatMap(tuple -> authTokenService.openSession(user, passkeyId, tuple.getT1(), tuple.getT2()))
                .flatMap(session -> auditService.record(AuthAuditEvents.ENTITY_SESSION, session.sessionId(),
                                AuthAuditEvents.ACCESS_GRANTED, user.getId(),
                                Map.of("passkey_id", passkeyId.toString(), "method", method))
                        .thenReturn(session));
    }

    static Mono<String> currentTenant() {
        return Mono.deferContextual(ctx -> ctx.<String>getOrEmpty(ReactorContextKeys.TENANT_DOMAIN)
                .map(Mono::just)
                .orElseGet(() -> Mono.error(new IllegalStateException("No tenant resolved for the request"))));
    }

    private Mono<Void> endReplacedSession(String replacedRefreshToken) {
        return authTokenService.findRefreshToken(replacedRefreshToken)
                .filter(token -> !token.isRevoked())
                .flatMap(token -> authTokenService.endSession(token.getSessionId())
                        .filter(Boolean::booleanValue)
                        .flatMap(_ -> auditService.record(AuthAuditEvents.ENTITY_SESSION, token.getSessionId(),
                                AuthAuditEvents.SESSION_ENDED, token.getUserId(),
                                Map.of("reason", "replaced_by_new_session"))))
                .then();
    }
}
