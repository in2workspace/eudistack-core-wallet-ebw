package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.exception.CredentialNotFoundException;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class DeleteCredentialWorkflow {

    private static final Logger log = LoggerFactory.getLogger(DeleteCredentialWorkflow.class);

    private final WalletCredentialRepository credentialRepository;
    private final PasskeyCustodyPolicy custodyPolicy;
    private final CredentialRemover credentialRemover;

    /**
     * Deletes the attestation and its key material in one transaction (EUD-11 FR-10, FR-16). With passkey
     * custody, an attestation of another passkey is answered as not found (FR-14).
     */
    public Mono<Void> deleteCredential(UUID userId, UUID sessionPasskeyId, UUID credentialId) {
        return credentialRepository.findByIdAndUserId(credentialId, userId)
                .flatMap(credential -> custodyPolicy.visibleToSession(credential, sessionPasskeyId))
                .switchIfEmpty(Mono.error(new CredentialNotFoundException()))
                .flatMap(credential -> credentialRemover.remove(credential, Map.of()))
                .doOnSuccess(v -> log.info("Credential deleted: id={}, userId={}", credentialId, userId))
                .doOnError(e -> log.error("Failed to delete credential: id={}, userId={}, error={}", credentialId, userId, e.getMessage()));
    }
}
