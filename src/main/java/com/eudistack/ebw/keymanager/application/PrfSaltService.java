package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.exception.PrfSaltNotFoundException;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent.KeyAuditEventType;
import com.eudistack.ebw.keymanager.domain.model.PrfSalt;
import com.eudistack.ebw.keymanager.domain.port.KeyAuditPort;
import reactor.core.publisher.Mono;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Application service implementing {@link PrfSaltUseCase}.
 *
 * <p>Concurrent creations of the salt of the same attestation are resolved by the composite primary
 * key: the losing insert is ignored and the winner's row is read. A salt that belongs to another
 * passkey is answered as if it did not exist, so a session cannot tell whether it exists.</p>
 *
 * <p>The salt bytes MUST NOT appear in any log message, error body, metric label or audit event.</p>
 */
public class PrfSaltService implements PrfSaltUseCase {

    static final String REASON_NOT_FOUND = "NOT_FOUND";
    static final String REASON_OTHER_PASSKEY = "OTHER_PASSKEY";
    static final String REASON_NO_PUBLIC_KEY = "NO_PUBLIC_KEY";

    private static final int SALT_BYTES = 32;

    private final PrfSaltPort prfSaltPort;
    private final KeyAuditPort auditPort;
    private final SecureRandom secureRandom = new SecureRandom();

    public PrfSaltService(PrfSaltPort prfSaltPort, KeyAuditPort auditPort) {
        this.prfSaltPort = prfSaltPort;
        this.auditPort = auditPort;
    }

    @Override
    public Mono<PrfSalt> createForPasskey(String tenantId, String holderId, String passkeyId, String credentialId) {
        return prfSaltPort.findBy(holderId, credentialId)
                .map(existing -> new Outcome(existing, false))
                .switchIfEmpty(Mono.defer(() -> insert(holderId, passkeyId, credentialId)))
                .flatMap(outcome -> outcome.salt().isOwnedBy(passkeyId)
                        ? deliver(outcome, tenantId, holderId, credentialId)
                        : deny(tenantId, holderId, credentialId, REASON_OTHER_PASSKEY));
    }

    @Override
    public Mono<PrfSalt> getForPasskey(String tenantId, String holderId, String passkeyId, String credentialId) {
        return prfSaltPort.findBy(holderId, credentialId)
                .map(Optional::of)
                .defaultIfEmpty(Optional.empty())
                .flatMap(found -> {
                    String denial = denialOf(found, passkeyId);
                    return denial == null
                            ? emit(KeyAuditEventType.SALT_DELIVERED, tenantId, holderId, credentialId, null)
                                    .thenReturn(found.get())
                            : deny(tenantId, holderId, credentialId, denial);
                });
    }

    private Mono<Outcome> insert(String holderId, String passkeyId, String credentialId) {
        byte[] salt = new byte[SALT_BYTES];
        secureRandom.nextBytes(salt);
        return prfSaltPort.insert(holderId, credentialId, passkeyId, salt)
                .flatMap(inserted -> prfSaltPort.findBy(holderId, credentialId)
                        .map(found -> new Outcome(found, inserted)))
                .switchIfEmpty(Mono.error(new PrfSaltNotFoundException(credentialId)));
    }

    private static String denialOf(Optional<PrfSalt> found, String passkeyId) {
        if (found.isEmpty()) {
            return REASON_NOT_FOUND;
        }
        if (!found.get().isOwnedBy(passkeyId)) {
            return REASON_OTHER_PASSKEY;
        }
        return found.get().publicJwk() == null ? REASON_NO_PUBLIC_KEY : null;
    }

    private Mono<PrfSalt> deliver(Outcome outcome, String tenantId, String holderId, String credentialId) {
        KeyAuditEventType type = outcome.created() ? KeyAuditEventType.SALT_CREATED : KeyAuditEventType.SALT_DELIVERED;
        return emit(type, tenantId, holderId, credentialId, null).thenReturn(outcome.salt());
    }

    private Mono<PrfSalt> deny(String tenantId, String holderId, String credentialId, String reason) {
        return emit(KeyAuditEventType.SALT_DELIVERY_DENIED, tenantId, holderId, credentialId, reason)
                .then(Mono.error(new PrfSaltNotFoundException(credentialId)));
    }

    /** Audit is best effort: a broken audit channel must not fail the operation. */
    private Mono<Void> emit(KeyAuditEventType type, String tenantId, String holderId, String credentialId,
                            String reason) {
        return Mono.defer(() -> auditPort.emit(KeyAuditEvent.forSalt(type, tenantId, holderId, credentialId, reason,
                        Instant.now(), UUID.randomUUID().toString())))
                .onErrorResume(e -> Mono.empty());
    }

    private record Outcome(PrfSalt salt, boolean created) {
    }
}
