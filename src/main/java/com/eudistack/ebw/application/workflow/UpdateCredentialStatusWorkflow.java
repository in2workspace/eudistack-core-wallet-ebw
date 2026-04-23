package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.model.WalletCredential;
import com.eudistack.ebw.domain.model.exception.CredentialNotFoundException;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.CredentialService;
import com.eudistack.ebw.domain.spi.CredentialEncryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Service
public class UpdateCredentialStatusWorkflow {

    private static final Logger log = LoggerFactory.getLogger(UpdateCredentialStatusWorkflow.class);

    private final WalletCredentialRepository credentialRepository;
    private final CredentialEncryptor encryptor;
    private final CredentialService credentialService;
    private final AuditService auditService;

    public UpdateCredentialStatusWorkflow(WalletCredentialRepository credentialRepository,
                                           CredentialEncryptor encryptor,
                                           CredentialService credentialService,
                                           AuditService auditService) {
        this.credentialRepository = credentialRepository;
        this.encryptor = encryptor;
        this.credentialService = credentialService;
        this.auditService = auditService;
    }

    public Mono<WalletCredential> updateStatus(UUID userId, UUID credentialId, String newStatusStr) {
        CredentialStatus newStatus;
        try {
            newStatus = CredentialStatus.valueOf(newStatusStr);
        } catch (IllegalArgumentException e) {
            return Mono.error(new IllegalArgumentException("Invalid status: " + newStatusStr));
        }

        return credentialRepository.findByIdAndUserId(credentialId, userId)
                .switchIfEmpty(Mono.error(new CredentialNotFoundException()))
                .flatMap(credential -> {
                    var oldStatus = credential.getStatus();
                    credentialService.validateStatusTransition(oldStatus, newStatus);

                    credential.setStatus(newStatus);
                    credential.setUpdatedAt(Instant.now());

                    var decrypted = encryptor.decrypt(credential.getCredentialRaw());
                    var entityHash = credentialService.computeAuditHash(decrypted);

                    return credentialRepository.update(credential)
                            .flatMap(saved -> auditService.record("credential", credentialId,
                                            "STATUS_CHANGED", userId,
                                            Map.of("entity_hash", "sha256:" + entityHash,
                                                    "old_status", oldStatus.name(),
                                                    "new_status", newStatus.name()))
                                    .thenReturn(saved));
                })
                .doOnSuccess(c -> log.info("Credential status updated: id={}, userId={}, newStatus={}",
                        credentialId, userId, newStatusStr))
                .doOnError(e -> log.error("Failed to update credential status: id={}, userId={}, error={}", credentialId, userId, e.getMessage()));
    }
}
