package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.exception.LastPasskeyException;
import com.eudistack.ebw.domain.model.exception.PasskeyNotFoundException;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.AuthTokenService;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

@Service
public class DeletePasskeyWorkflow {

    private final UserPasskeyRepository passkeyRepository;
    private final AuthTokenService authTokenService;
    private final AuditService auditService;

    public DeletePasskeyWorkflow(UserPasskeyRepository passkeyRepository,
                                 AuthTokenService authTokenService,
                                 AuditService auditService) {
        this.passkeyRepository = passkeyRepository;
        this.authTokenService = authTokenService;
        this.auditService = auditService;
    }

    public Mono<Void> deletePasskey(UUID userId, UUID passkeyId) {
        return passkeyRepository.findByIdAndUserId(passkeyId, userId)
                .switchIfEmpty(Mono.error(new PasskeyNotFoundException()))
                .flatMap(passkey -> passkeyRepository.countByUserId(userId)
                        .flatMap(count -> {
                            if (count <= 1) {
                                return Mono.error(new LastPasskeyException());
                            }
                            return authTokenService.revokeAllByPasskey(passkeyId)
                                    .then(passkeyRepository.deleteById(passkeyId))
                                    .then(auditService.record("passkey", passkeyId,
                                            "PASSKEY_DELETED", userId,
                                            Map.of("display_name", passkey.getDisplayName())));
                        }));
    }
}
