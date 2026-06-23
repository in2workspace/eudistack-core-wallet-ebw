package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.keymanager.application.PrfSaltPort;
import io.r2dbc.spi.R2dbcException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * R2DBC adapter for the {@code hybrid_prf_salt} table, implementing {@link PrfSaltPort}.
 *
 * <p>Uses raw {@link DatabaseClient} SQL because the table has a composite primary key
 * ({@code holder_id, credential_id}), which Spring Data R2DBC does not support natively
 * (AD-4, technical-design.md §3.2). Tenant isolation is via PostgreSQL {@code search_path}
 * set by {@code TenantAwareConnectionFactoryDecorator} (architecture.md §5.3).</p>
 *
 * <p>Duplicate-key on INSERT is a benign signal in the get-or-create scenario (EC-03):
 * when two concurrent init requests race, the loser swallows the
 * {@link DataIntegrityViolationException} and the caller re-SELECTs to obtain the
 * winner's value.</p>
 *
 * <p>Spec: EUDISTACK-537 AC-01, AC-02, EC-03, ES-05, NFR-S-537-05; architecture.md §5.3.</p>
 */
public class PrfSaltRepository implements PrfSaltPort {

    private static final String SELECT_SQL =
            "SELECT prf_salt FROM hybrid_prf_salt "
            + "WHERE holder_id = :holderId AND credential_id = :credentialId";

    private static final String INSERT_SQL =
            "INSERT INTO hybrid_prf_salt (holder_id, credential_id, prf_salt) "
            + "VALUES (:holderId, :credentialId, :prfSalt)";

    private static final String COUNT_SQL =
            "SELECT COUNT(*) FROM hybrid_prf_salt WHERE credential_id = :credentialId";

    private final DatabaseClient databaseClient;

    public PrfSaltRepository(DatabaseClient databaseClient) {
        this.databaseClient = databaseClient;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Executes {@code SELECT prf_salt … WHERE holder_id = ? AND credential_id = ?}.
     * Returns an empty Mono when no row exists for the given composite key.</p>
     */
    @Override
    public Mono<byte[]> findBy(String holderId, String credentialId) {
        return databaseClient.sql(SELECT_SQL)
                .bind("holderId", UUID.fromString(holderId))
                .bind("credentialId", credentialId)
                .map((row, metadata) -> row.get("prf_salt", byte[].class))
                .one();
    }

    /**
     * {@inheritDoc}
     *
     * <p>Executes {@code INSERT INTO hybrid_prf_salt …}. A
     * {@link DataIntegrityViolationException} caused by a duplicate composite key
     * (SQLSTATE 23505) is swallowed silently — the caller must re-SELECT to obtain the
     * persisted value (EC-03). Any other integrity violation (e.g. FK violation 23503,
     * CHECK violation 23514) propagates as-is so the caller is not misled.</p>
     */
    @Override
    public Mono<Void> insert(String holderId, String credentialId, byte[] prfSalt) {
        return databaseClient.sql(INSERT_SQL)
                .bind("holderId", UUID.fromString(holderId))
                .bind("credentialId", credentialId)
                .bind("prfSalt", prfSalt)
                .fetch()
                .rowsUpdated()
                .then()
                .onErrorResume(
                        ex -> ex instanceof DataIntegrityViolationException && isUniqueViolation(ex),
                        ex -> Mono.empty());
    }

    /**
     * Returns {@code true} only when the root cause is an R2DBC unique-constraint violation
     * (SQLSTATE {@code 23505}). Traverses the cause chain because Spring's
     * {@link DataIntegrityViolationException} wraps the underlying {@link R2dbcException}.
     */
    private boolean isUniqueViolation(Throwable ex) {
        Throwable cause = ex;
        while (cause != null) {
            if (cause instanceof R2dbcException r2dbc && "23505".equals(r2dbc.getSqlState())) {
                return true;
            }
            cause = cause.getCause();
        }
        return false;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Executes {@code SELECT COUNT(*) … WHERE credential_id = ?}.</p>
     */
    @Override
    public Mono<Long> countByCredential(String credentialId) {
        return databaseClient.sql(COUNT_SQL)
                .bind("credentialId", credentialId)
                .map((row, metadata) -> row.get(0, Long.class))
                .one();
    }
}
