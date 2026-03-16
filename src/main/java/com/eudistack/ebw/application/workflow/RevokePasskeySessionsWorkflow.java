package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.exception.PasskeyNotFoundException;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.service.AuditService;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

@Service
public class RevokePasskeySessionsWorkflow {

    private final UserPasskeyRepository passkeyRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AuditService auditService;

    public RevokePasskeySessionsWorkflow(UserPasskeyRepository passkeyRepository,
                                         RefreshTokenRepository refreshTokenRepository,
                                         AuditService auditService) {
        this.passkeyRepository = passkeyRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.auditService = auditService;
    }

    public Mono<Void> revokeSessions(UUID userId, UUID passkeyId) {
        return passkeyRepository.findByIdAndUserId(passkeyId, userId)
                .switchIfEmpty(Mono.error(new PasskeyNotFoundException()))
                .flatMap(passkey -> refreshTokenRepository.revokeByPasskeyId(passkeyId)
                        .then(auditService.record("passkey", passkeyId,
                                "SESSIONS_REVOKED", userId, Map.of())));
    }
}
