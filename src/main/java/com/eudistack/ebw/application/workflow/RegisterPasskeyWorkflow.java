package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.exception.DuplicatePasskeyException;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.service.AuditService;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

@Service
public class RegisterPasskeyWorkflow {

    private final UserPasskeyRepository passkeyRepository;
    private final AuditService auditService;

    public RegisterPasskeyWorkflow(UserPasskeyRepository passkeyRepository, AuditService auditService) {
        this.passkeyRepository = passkeyRepository;
        this.auditService = auditService;
    }

    public Mono<UserPasskey> registerPasskey(UUID userId, String credentialId, String displayName, String userAgent) {
        return passkeyRepository.findByUserIdAndCredentialId(userId, credentialId)
                .flatMap(existing -> Mono.<UserPasskey>error(new DuplicatePasskeyException()))
                .switchIfEmpty(Mono.defer(() -> {
                    var passkey = UserPasskey.create(userId, credentialId, displayName, userAgent);
                    return passkeyRepository.save(passkey)
                            .flatMap(saved -> auditService.record("passkey", saved.getId(),
                                    "PASSKEY_CREATED", userId,
                                    Map.of("display_name", displayName)).thenReturn(saved));
                }));
    }
}
