package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.AuthTokenService;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

/** Ends the current session, or every other session of the account (FR-11, FR-20). */
@Service
public class EndSessionWorkflow {

    private final AuthTokenService authTokenService;
    private final AuditService auditService;

    public EndSessionWorkflow(AuthTokenService authTokenService, AuditService auditService) {
        this.authTokenService = authTokenService;
        this.auditService = auditService;
    }

    /** Audits {@code SESSION_ENDED} only when this call ended the session, never for an already ended one. */
    public Mono<Void> endCurrentSession(UUID userId, UUID sessionId) {
        return authTokenService.endSession(sessionId)
                .filter(Boolean::booleanValue)
                .flatMap(_ -> auditService.record(AuthAuditEvents.ENTITY_SESSION, sessionId,
                        AuthAuditEvents.SESSION_ENDED, userId, Map.of("reason", "sign_out")));
    }

    public Mono<Void> endOtherSessions(UUID userId, UUID currentSessionId) {
        return authTokenService.endOtherSessions(userId, currentSessionId)
                .defaultIfEmpty(0L)
                .flatMap(revoked -> auditService.record(AuthAuditEvents.ENTITY_USER, userId,
                        AuthAuditEvents.OTHER_SESSIONS_ENDED, userId,
                        Map.of("kept_session_id", currentSessionId.toString(), "revoked_tokens", revoked)));
    }
}
