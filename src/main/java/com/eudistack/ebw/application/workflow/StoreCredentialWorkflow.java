package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.CustodyMode;
import com.eudistack.ebw.domain.model.WalletCredential;
import com.eudistack.ebw.domain.model.exception.UnsupportedFormatException;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.CredentialService;
import com.eudistack.ebw.domain.service.CredentialService.ParsedCredential;
import com.eudistack.ebw.domain.service.TenantConfigService;
import com.eudistack.ebw.domain.spi.HolderKeyMaterialPort;
import com.eudistack.ebw.domain.spi.HolderKeyMaterialPort.Binding;
import com.eudistack.ebw.domain.spi.TransactionRunner;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
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
    private final PasskeyCustodyPolicy custodyPolicy;
    private final HolderKeyMaterialPort holderKeyMaterial;
    private final TransactionRunner transactionRunner;

    /**
     * Stores an attestation. When it is bound to the holder (has {@code cnf}, or was issued with a
     * holder key), it is stored with the passkey of the session that obtained it (EUD-11 FR-13) and
     * the custody mode of the tenant (FR-03); the Wallet App never sends the passkey.
     *
     * <p>With custody, an attestation whose {@code cnf} is not the key of its holder key is rejected
     * and nothing is stored (FR-05).
     *
     * @param sessionPasskeyId passkey of the session ({@code pkid} of the access token)
     * @param holderPublicJwk  public key the Wallet App derived; only with passkey custody
     */
    @SuppressWarnings("java:S107")
    public Mono<WalletCredential> storeCredential(UUID userId, String credentialRaw, String format,
                                                    String credentialConfigId, String kid,
                                                    Map<String, Object> issuerMetadata, String holderKeyId,
                                                    Map<String, Object> holderPublicJwk,
                                                    UUID sessionPasskeyId) {
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
                        .flatMap(parsed -> custodyModeOf(parsed, holderKeyId)
                                .flatMap(mode -> {
                                    var credential = WalletCredential.create(userId, credentialRaw, credentialFormat,
                                            credentialConfigId, kid, parsed.credentialType(), parsed.vct(),
                                            parsed.issuer(), parsed.subject(), parsed.issuanceDate(),
                                            parsed.expirationDate(), issuerMetadata, holderKeyId,
                                            parsed.hasCnf() || holderKeyId != null, sessionPasskeyId,
                                            mode.orElse(null));
                                    return mode.isPresent() && parsed.hasCnf()
                                            ? verifyAndStore(credential, new Binding(mode.get(), userId,
                                                    sessionPasskeyId, holderKeyId, parsed.cnfJwk(), holderPublicJwk))
                                            : credentialRepository.insert(credential);
                                }))
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

    /** Custody mode of a bound attestation; empty when it is not bound or the tenant has no custody. */
    private Mono<Optional<CustodyMode>> custodyModeOf(ParsedCredential parsed, String holderKeyId) {
        if (!parsed.hasCnf() && holderKeyId == null) {
            return Mono.just(Optional.empty());
        }
        return custodyPolicy.custodyMode().map(Optional::of).defaultIfEmpty(Optional.empty());
    }

    private Mono<WalletCredential> verifyAndStore(WalletCredential credential, Binding binding) {
        return holderKeyMaterial.verify(binding)
                .then(Mono.defer(() -> transactionRunner.inTransaction(credentialRepository.insert(credential)
                        .flatMap(saved -> holderKeyMaterial.keepPublicKey(binding).thenReturn(saved)))));
    }
}
