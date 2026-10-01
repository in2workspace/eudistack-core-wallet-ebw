package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.exception.PasskeyNotFoundException;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.AuthTokenService;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

@Service
public class RevokePasskeySessionsWorkflow {

    private final UserPasskeyRepository passkeyRepository;
    private final AuthTokenService authTokenService;
    private final AuditService auditService;

    public RevokePasskeySessionsWorkflow(UserPasskeyRepository passkeyRepository,
                                         AuthTokenService authTokenService,
                                         AuditService auditService) {
        this.passkeyRepository = passkeyRepository;
        this.authTokenService = authTokenService;
        this.auditService = auditService;
    }

    public Mono<Void> revokeSessions(UUID userId, UUID passkeyId) {
        return passkeyRepository.findByIdAndUserId(passkeyId, userId)
                .switchIfEmpty(Mono.error(new PasskeyNotFoundException()))
                .flatMap(passkey -> authTokenService.revokeAllByPasskey(passkeyId)
                        .then(auditService.record("passkey", passkeyId,
                                "SESSIONS_REVOKED", userId, Map.of())));
    }
}
