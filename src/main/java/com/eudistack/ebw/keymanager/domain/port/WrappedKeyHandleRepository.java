package com.eudistack.ebw.keymanager.domain.port;

import com.eudistack.ebw.keymanager.domain.model.WrappedKeyHandle;
import reactor.core.publisher.Mono;

import java.util.Optional;

/**
 * Write + read port for wrapped key handle persistence.
 *
 * <p>One handle per {@code (holderId, credentialId)} composite — enforced by
 * the {@code hybrid_wrapped_key_handle} primary key (US-03 / EUDISTACK-535 DDL).
 * Tenant isolation is via PostgreSQL {@code search_path} (architecture.md §5.3).
 * A duplicate INSERT propagates a {@link org.springframework.dao.DataIntegrityViolationException}
 * to the use case, which maps it to an
 * {@link com.eudistack.ebw.keymanager.domain.exception.OnboardingStateException}.</p>
 *
 * <p>The {@link #insert} method is intentionally non-upsert: the idempotency check
 * (identical blob → 200 ACK, different blob → 409) is done by
 * {@link com.eudistack.ebw.keymanager.application.EnrollHolderUseCase} before calling
 * this port (AC-07, ES-03).</p>
 *
 * <p>Spec: EUDISTACK-534 AC-04, AC-07; architecture.md §5.3.</p>
 */
public interface WrappedKeyHandleRepository {

    /**
     * Returns the existing handle for the given composite key, or {@link Optional#empty()}
     * if none has been committed yet.
     *
     * <p>Tenant isolation is provided by the PostgreSQL {@code search_path} set on each
     * connection by {@code TenantAwareConnectionFactoryDecorator} (architecture.md §5.3).</p>
     *
     * @param holderId     holder within the current tenant schema
     * @param credentialId the credential being enrolled
     */
    Mono<Optional<WrappedKeyHandle>> findBy(String holderId, String credentialId);

    /**
     * Inserts a new wrapped key handle.
     *
     * <p>Precondition: no handle exists for the same {@code (holderId, credentialId)}.
     * The caller ({@link com.eudistack.ebw.keymanager.application.EnrollHolderUseCase}) is
     * responsible for checking {@link #findBy} before calling this method.</p>
     *
     * @param handle the domain aggregate to persist
     * @return empty {@code Mono<Void>} on success; propagates
     *         {@link org.springframework.dao.DataIntegrityViolationException} on constraint
     *         violation (concurrent duplicate)
     */
    Mono<Void> insert(WrappedKeyHandle handle);

    /**
     * Returns the total number of wrapped key handles in the current tenant schema.
     *
     * <p>Tenant isolation is provided by the PostgreSQL {@code search_path} set on each
     * connection by {@code TenantAwareConnectionFactoryDecorator} (architecture.md §5.3).
     * Used by {@code HybridHealthContributor} (US-09) to expose the {@code wrap_handles_total}
     * operational indicator.</p>
     *
     * @return total row count in {@code hybrid_wrapped_key_handle} for the current tenant
     */
    Mono<Long> count();
}