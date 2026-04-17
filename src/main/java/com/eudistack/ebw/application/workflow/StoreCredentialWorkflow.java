package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.WalletCredential;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.CredentialService;
import com.eudistack.ebw.domain.spi.CredentialEncryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

@Service
public class StoreCredentialWorkflow {

    private static final Logger log = LoggerFactory.getLogger(StoreCredentialWorkflow.class);

    private final CredentialService credentialService;
    private final CredentialEncryptor encryptor;
    private final WalletCredentialRepository credentialRepository;
    private final AuditService auditService;

    public StoreCredentialWorkflow(CredentialService credentialService,
                                    CredentialEncryptor encryptor,
                                    WalletCredentialRepository credentialRepository,
                                    AuditService auditService) {
        this.credentialService = credentialService;
        this.encryptor = encryptor;
        this.credentialRepository = credentialRepository;
        this.auditService = auditService;
    }

    public Mono<WalletCredential> storeCredential(UUID userId, String credentialRaw, String format,
                                                    String credentialConfigId, String kid,
                                                    Map<String, Object> issuerMetadata) {
        var credentialFormat = credentialService.validateFormat(format);

        return credentialService.parseCredential(credentialRaw, credentialFormat)
                .map(parsed -> {
                    var encrypted = encryptor.encrypt(credentialRaw);
                    return WalletCredential.create(userId, encrypted, credentialFormat,
                            credentialConfigId, kid, parsed.credentialType(), parsed.vct(),
                            parsed.issuer(), parsed.subject(), parsed.issuanceDate(),
                            parsed.expirationDate(), issuerMetadata);
                })
                .flatMap(credentialRepository::save)
                .flatMap(saved -> {
                    var entityHash = credentialService.computeAuditHash(credentialRaw);
                    return auditService.record("credential", saved.getId(), "CREATED", userId,
                                    Map.of("entity_hash", "sha256:" + entityHash,
                                            "format", format,
                                            "credential_type", saved.getCredentialType()))
                            .thenReturn(saved);
                })
                .doOnSuccess(c -> log.info("Credential stored: id={}, userId={}, type={}",
                        c.getId(), userId, c.getCredentialType()));
    }
}
