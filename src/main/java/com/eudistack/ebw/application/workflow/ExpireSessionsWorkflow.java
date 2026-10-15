package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.AuthTokenService;
import com.eudistack.ebw.domain.service.WalletAuthSettingsService;
import com.eudistack.ebw.domain.spi.TransactionRunner;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Records {@code SESSION_EXPIRED} for the sessions of the current tenant that lapsed without
 * anyone trying to renew them (FR-22): closes them and audits each one with the limit it reached,
 * {@code idle_timeout} or {@code max_duration}. Closing and auditing share one transaction, so a
 * failed audit leaves the session for the next pass. A session already closed by a renewal
 * attempt ({@link RefreshTokenWorkflow}) or by an earlier pass is not closed, nor audited, again.
 */
@Service
public class ExpireSessionsWorkflow {

    private final AuthTokenService authTokenService;
    private final WalletAuthSettingsService settingsService;
    private final AuditService auditService;
    private final TransactionRunner transactionRunner;

    public ExpireSessionsWorkflow(AuthTokenService authTokenService, WalletAuthSettingsService settingsService,
                                  AuditService auditService, TransactionRunner transactionRunner) {
        this.authTokenService = authTokenService;
        this.settingsService = settingsService;
        this.auditService = auditService;
        this.transactionRunner = transactionRunner;
    }

    /** Requires the tenant in the Reactor context. Emits the number of sessions expired. */
    public Mono<Long> expireLapsedSessions() {
        return settingsService.session()
                .flatMap(settings -> transactionRunner.inTransaction(authTokenService.expireLapsedSessions()
                        .concatMap(session -> auditService.record(AuthAuditEvents.ENTITY_SESSION, session.sessionId(),
                                        AuthAuditEvents.SESSION_EXPIRED, session.userId(),
                                        Map.of("reason", session.reason(settings.maxDuration()).code()))
                                .thenReturn(session))
                        .count()));
    }
}
