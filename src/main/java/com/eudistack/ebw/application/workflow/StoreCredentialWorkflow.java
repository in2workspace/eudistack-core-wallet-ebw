package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.WalletCredential;
import com.eudistack.ebw.domain.model.exception.UnsupportedFormatException;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.CredentialService;
import com.eudistack.ebw.domain.service.TenantConfigService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class StoreCredentialWorkflow {

    private static final Logger log = LoggerFactory.getLogger(StoreCredentialWorkflow.class);
    private static final String DEFAULT_ALLOWED_FORMATS = "dc+sd-jwt,jwt_vc_json";

    private final CredentialService credentialService;
    private final TenantConfigService tenantConfigService;
    private final WalletCredentialRepository credentialRepository;
    private final AuditService auditService;

    public Mono<WalletCredential> storeCredential(UUID userId, String credentialRaw, String format,
                                                    String credentialConfigId, String kid,
                                                    Map<String, Object> issuerMetadata, String holderKeyId) {
        return Mono.fromCallable(() -> credentialService.validateFormat(format))
                .flatMap(credentialFormat ->
                        tenantConfigService.getStringOrDefault("ebw.allowed_credential_formats", DEFAULT_ALLOWED_FORMATS)
                                .flatMap(allowed -> {
                                    if (!allowed.equals("*")) {
                                        boolean permitted = Arrays.stream(allowed.split(","))
                                                .map(String::trim)
                                                .anyMatch(f -> f.equalsIgnoreCase(credentialFormat.getValue()));
                                        if (!permitted) {
                                            return Mono.error(new UnsupportedFormatException(format));
                                        }
                                    }
                                    return credentialService.parseCredential(credentialRaw, credentialFormat);
                                })
                        .map(parsed -> {
                            return WalletCredential.create(userId, credentialRaw, credentialFormat,
                                    credentialConfigId, kid, parsed.credentialType(), parsed.vct(),
                                    parsed.issuer(), parsed.subject(), parsed.issuanceDate(),
                                    parsed.expirationDate(), issuerMetadata, holderKeyId);
                        })
                        .flatMap(credentialRepository::insert)
                        .flatMap(saved -> {
                            var entityHash = credentialService.computeAuditHash(credentialRaw);
                            return auditService.record("credential", saved.getId(), "CREATED", userId,
                                            Map.of("entity_hash", "sha256:" + entityHash,
                                                    "format", format,
                                                    "credential_type", saved.getCredentialType()))
                                    .thenReturn(saved);
                        }))
                .doOnSuccess(c -> log.info("Credential stored: id={}, userId={}, type={}",
                        c.getId(), userId, c.getCredentialType()))
                .doOnError(e -> log.error("Failed to store credential: userId={}, error={}", userId, e.getMessage()));
    }
}
