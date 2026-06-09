package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.exception.CredentialNotFoundException;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.CredentialService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

@Service
public class DeleteCredentialWorkflow {

    private static final Logger log = LoggerFactory.getLogger(DeleteCredentialWorkflow.class);

    private final WalletCredentialRepository credentialRepository;
    private final CredentialService credentialService;
    private final AuditService auditService;

    public DeleteCredentialWorkflow(WalletCredentialRepository credentialRepository,
                                     CredentialService credentialService,
                                     AuditService auditService) {
        this.credentialRepository = credentialRepository;
        this.credentialService = credentialService;
        this.auditService = auditService;
    }

    public Mono<Void> deleteCredential(UUID userId, UUID credentialId) {
        return credentialRepository.findByIdAndUserId(credentialId, userId)
                .switchIfEmpty(Mono.error(new CredentialNotFoundException()))
                .flatMap(credential -> {
                    var entityHash = credentialService.computeAuditHash(credential.getCredentialRaw());

                    return auditService.record("credential", credentialId, "DELETED", userId,
                                    Map.of("entity_hash", "sha256:" + entityHash,
                                            "credential_type", credential.getCredentialType(),
                                            "issuer", credential.getIssuer(),
                                            "format", credential.getFormat().getValue(),
                                            "previous_status", credential.getStatus().name()))
                            .then(credentialRepository.deleteById(credentialId));
                })
                .doOnSuccess(v -> log.info("Credential deleted: id={}, userId={}", credentialId, userId))
                .doOnError(e -> log.error("Failed to delete credential: id={}, userId={}, error={}", credentialId, userId, e.getMessage()));
    }
}
