package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.exception.HolderIsolationViolationException;
import com.eudistack.ebw.keymanager.domain.exception.PrfSaltNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.security.SecureRandom;

/**
 * Application service implementing {@link PrfSaltUseCase}.
 *
 * <p>Provides two operations:
 * <ul>
 *   <li>{@link #getOrCreatePrfSalt} — get-or-create: returns the existing salt for
 *       {@code (tenantId, holderId, credentialId)}, generating and persisting a 32-byte
 *       CSPRNG salt on the first call. Concurrent races are resolved by the composite PK
 *       in the database: the losing INSERT is silently swallowed by {@link PrfSaltPort}
 *       and the winner's value is retrieved via a re-SELECT (EC-03).</li>
 *   <li>{@link #getForHolder} — read-only with holder isolation: returns the salt only
 *       for the requesting holder, distinguishing 404 (credential absent) from 403
 *       (credential exists but belongs to a different holder) via
 *       {@link PrfSaltPort#countByCredential} (AC-04, ES-04).</li>
 * </ul>
 *
 * <p>The {@link #getOrCreatePrfSalt} method is declared by {@link PrfSaltUseCase} (defined in
 * US-02/EUDISTACK-534). {@link #getForHolder} is an additional public method consumed by
 * {@code prepareSign} in US-04.</p>
 *
 * <p>Tenant isolation is enforced at the database level via PostgreSQL {@code search_path}
 * set by {@code TenantAwareConnectionFactoryDecorator}; {@code tenantId} is accepted for
 * traceability but is not forwarded to {@link PrfSaltPort} (architecture.md §5.3).</p>
 *
 * <p>The {@code prf_salt} bytes MUST NOT appear in any log message, error body, metric
 * label, or audit event (NFR-S-537-01, AC-06).</p>
 *
 * <p>Spec: EUDISTACK-537 AC-01, AC-02, AC-04, AC-05, EC-01, EC-03, ES-01, ES-02, ES-04,
 * ES-05, NFR-S-537-01, NFR-S-537-05; architecture.md §5.1, §6.1.</p>
 */
@Service
public class PrfSaltService implements PrfSaltUseCase {

    private static final Logger log = LoggerFactory.getLogger(PrfSaltService.class);
    private static final int SALT_BYTES = 32;

    private final PrfSaltPort prfSaltPort;
    private final SecureRandom secureRandom;

    public PrfSaltService(PrfSaltPort prfSaltPort) {
        this.prfSaltPort = prfSaltPort;
        this.secureRandom = new SecureRandom();
    }

    /**
     * {@inheritDoc}
     *
     * <p>Flow: SELECT → hit → return bytes; miss → generate 32-byte CSPRNG salt →
     * INSERT (duplicate swallowed) → re-SELECT to obtain the persisted value.
     * The re-SELECT guarantees idempotency under concurrent init requests (EC-01, EC-03).</p>
     */
    @Override
    public Mono<byte[]> getOrCreatePrfSalt(String tenantId, String holderId, String credentialId) {
        return prfSaltPort.findBy(holderId, credentialId)
                .switchIfEmpty(generateAndInsert(holderId, credentialId));
    }

    /**
     * Returns the PRF salt for the requesting holder, enforcing holder isolation.
     *
     * <p>If the composite key {@code (holderId, credentialId)} is absent:
     * <ul>
     *   <li>If {@code countByCredential} == 0 → credential does not exist → 404
     *       {@link PrfSaltNotFoundException}.</li>
     *   <li>If {@code countByCredential} > 0 → credential exists for another holder →
     *       403 {@link HolderIsolationViolationException} (AC-04, NFR-S-537-02).</li>
     * </ul>
     *
     * <p>{@code tenantId} is accepted for traceability; tenant isolation is enforced by
     * the database {@code search_path} (architecture.md §5.3).</p>
     *
     * @param tenantId     the tenant (from Reactor context — for traceability only)
     * @param holderId     the holder UUID (DPoP-bound, from controller — never from body)
     * @param credentialId the credential identifier
     * @return 32-byte raw PRF salt; never empty
     */
    public Mono<byte[]> getForHolder(String tenantId, String holderId, String credentialId) {
        return prfSaltPort.findBy(holderId, credentialId)
                .switchIfEmpty(resolveAbsence(holderId, credentialId));
    }

    private Mono<byte[]> generateAndInsert(String holderId, String credentialId) {
        byte[] salt = new byte[SALT_BYTES];
        secureRandom.nextBytes(salt);
        return prfSaltPort.insert(holderId, credentialId, salt)
                .then(prfSaltPort.findBy(holderId, credentialId))
                .doOnSuccess(found ->
                        log.debug("keymanager.prf_salt.get_or_create holder_present=true credential_id_hash={}",
                                credentialId.hashCode()));
    }

    private Mono<byte[]> resolveAbsence(String holderId, String credentialId) {
        return prfSaltPort.countByCredential(credentialId)
                .flatMap(count -> {
                    if (count > 0) {
                        log.debug("keymanager.prf_salt.isolation_violation credential_id_hash={}",
                                credentialId.hashCode());
                        return Mono.error(new HolderIsolationViolationException(credentialId));
                    }
                    log.debug("keymanager.prf_salt.not_found credential_id_hash={}",
                            credentialId.hashCode());
                    return Mono.error(new PrfSaltNotFoundException(credentialId));
                });
    }
}
