package com.eudistack.ebw.wallet.config.domain.port;

import com.eudistack.ebw.wallet.config.domain.model.ConfigurationAuditEvent;
import reactor.core.publisher.Mono;

/**
 * Output port — append-only audit log for wallet configuration changes.
 *
 * <p>Each call to {@link #append} inserts a new row into the tenant's
 * {@code <schema>.wallet_config_audit} table. The table's DDL includes a trigger that
 * rejects {@code UPDATE} and {@code DELETE} operations (AC-3e).
 *
 * <p>This interface is intentionally append-only: there is no {@code delete} or {@code update}
 * method. Domain callers invoke this port after a successful configuration mutation and also
 * when a cache invalidation attempt is exhausted (AC-4c).
 *
 * <p>Zero framework imports — domain layer interface only.
 * The implementing adapter lives in {@code infrastructure/persistence}.
 */
public interface ConfigurationAuditPort {

    /**
     * Appends a new audit entry.
     *
     * <p>The method must never modify or overwrite existing entries. Implementations
     * must perform an {@code INSERT} only.
     *
     * @param event the audit event to persist; must not be {@code null}
     * @return a {@link Mono} that completes when the entry has been persisted
     */
    Mono<Void> append(ConfigurationAuditEvent event);
}
