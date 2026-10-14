package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.IssuedSession;
import com.eudistack.ebw.domain.model.exception.InvalidSessionException;
import com.eudistack.ebw.domain.model.exception.SessionExpiredException;
import com.eudistack.ebw.domain.model.exception.TokenFamilyCompromisedException;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.AuthTokenService;
import com.eudistack.ebw.domain.service.WalletAuthSettingsService;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Renews the access token of the session of the refresh cookie (FR-18, FR-19). Any failure is
 * {@link InvalidSessionException}: missing, inactive for too long, past its maximum duration,
 * ended or reused (then the whole session is ended).
 */
@Service
public class RefreshTokenWorkflow {

    private final AuthTokenService authTokenService;
    private final WalletUserRepository userRepository;
    private final WalletAuthSettingsService settingsService;
    private final AuditService auditService;

    public RefreshTokenWorkflow(AuthTokenService authTokenService, WalletUserRepository userRepository,
                                WalletAuthSettingsService settingsService, AuditService auditService) {
        this.authTokenService = authTokenService;
        this.userRepository = userRepository;
        this.settingsService = settingsService;
        this.auditService = auditService;
    }

    public Mono<IssuedSession> refresh(String rawRefreshToken) {
        return authTokenService.findRefreshToken(rawRefreshToken)
                .switchIfEmpty(Mono.error(new InvalidSessionException()))
                .flatMap(token -> userRepository.findById(token.getUserId())
                        .switchIfEmpty(Mono.error(new InvalidSessionException()))
                        .flatMap(user -> Mono.zip(settingsService.session(), SessionOpener.currentTenant())
                                .flatMap(tuple -> authTokenService.rotateRefreshToken(token, user,
                                        tuple.getT1(), tuple.getT2()))))
                .onErrorResume(SessionExpiredException.class, e -> auditService.record(
                                AuthAuditEvents.ENTITY_SESSION, e.getSessionId(), AuthAuditEvents.SESSION_EXPIRED,
                                e.getUserId(), Map.of("reason", e.getReason().name().toLowerCase()))
                        .then(Mono.error(new InvalidSessionException())))
                .onErrorResume(TokenFamilyCompromisedException.class, e -> auditService.record(
                                AuthAuditEvents.ENTITY_SESSION, e.getSessionId(), AuthAuditEvents.SESSION_ENDED,
                                e.getUserId(), Map.of("reason", "refresh_token_reuse"))
                        .then(Mono.error(new InvalidSessionException())));
    }
}
