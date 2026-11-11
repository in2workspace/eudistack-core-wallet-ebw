package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Map;

/**
 * With passkey custody, an attestation bound to a passkey that is no longer in the account is not available
 * in any session. This deletes it, with its key material, once it has expired (EUD-328 FR-25). Orphans without
 * an expiration date are kept while the account exists. With server custody nothing is deleted.
 */
@Service
@RequiredArgsConstructor
public class PurgeOrphanCredentialsWorkflow {

    static final String AUDIT_REASON = "orphan_expired";

    private static final Logger log = LoggerFactory.getLogger(PurgeOrphanCredentialsWorkflow.class);

    private final PasskeyCustodyPolicy custodyPolicy;
    private final WalletCredentialRepository credentialRepository;
    private final CredentialRemover credentialRemover;

    /**
     * Requires the tenant in the Reactor context. A failure on one attestation is logged and does not stop the
     * rest. Emits the number of attestations deleted.
     */
    public Mono<Long> purgeExpiredOrphans(Instant now) {
        return custodyPolicy.isPasskeyCustody()
                .flatMap(passkeyCustody -> Boolean.TRUE.equals(passkeyCustody) ? purge(now) : Mono.just(0L));
    }

    private Mono<Long> purge(Instant now) {
        return credentialRepository.findOrphanedExpired(now)
                .concatMap(credential -> credentialRemover.remove(credential, Map.of("reason", AUDIT_REASON))
                        .thenReturn(credential.getId())
                        .onErrorResume(e -> {
                            log.warn("Could not purge orphan credential: id={}, error={}", credential.getId(), e.getMessage());
                            return Mono.empty();
                        }))
                .count();
    }
}
