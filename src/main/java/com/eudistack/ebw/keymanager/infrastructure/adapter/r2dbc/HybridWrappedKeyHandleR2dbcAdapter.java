package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.keymanager.domain.exception.OnboardingStateException;
import com.eudistack.ebw.keymanager.domain.model.WrappedKeyHandle;
import com.eudistack.ebw.keymanager.domain.port.WrappedKeyHandleRepository;
import io.r2dbc.spi.Row;
import io.r2dbc.spi.RowMetadata;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Optional;

/**
 * R2DBC adapter for the {@code hybrid_wrapped_key_handle} table.
 *
 * <p>Uses raw {@link DatabaseClient} SQL because the table has a composite primary key
 * ({@code holder_id, credential_id}), which Spring Data R2DBC does not support
 * natively (technical-design.md §3.2 AD-4). Tenant isolation is via PostgreSQL
 * {@code search_path} set by {@code TenantAwareConnectionFactoryDecorator} (architecture.md §5.3).</p>
 *
 * <p>The DDL for {@code hybrid_wrapped_key_handle} is provided by US-03 (EUDISTACK-535)
 * via a Flyway tenant migration. Tests use a temporary DDL stub until that migration lands.</p>
 *
 * <p>Spec: EUDISTACK-534 AC-04, AC-05; architecture.md §5.3.</p>
 */
public class HybridWrappedKeyHandleR2dbcAdapter implements WrappedKeyHandleRepository {

    private static final String COUNT_SQL =
            "SELECT COUNT(*) FROM hybrid_wrapped_key_handle";

    private static final String SELECT_SQL =
            "SELECT holder_id, credential_id, wrapped_blob, iv, tag, "
            + "kdf_algo, kdf_version, cnf_jwk, created_at, last_used_at "
            + "FROM hybrid_wrapped_key_handle "
            + "WHERE holder_id = :holderId AND credential_id = :credentialId";

    private static final String INSERT_SQL =
            "INSERT INTO hybrid_wrapped_key_handle "
            + "(holder_id, credential_id, wrapped_blob, iv, tag, "
            + " kdf_algo, kdf_version, cnf_jwk, created_at) "
            + "VALUES (:holderId, :credentialId, :wrappedBlob, :iv, :tag, "
            + " :kdfAlgo, :kdfVersion, :cnfJwk, :createdAt)";

    private final DatabaseClient databaseClient;

    public HybridWrappedKeyHandleR2dbcAdapter(DatabaseClient databaseClient) {
        this.databaseClient = databaseClient;
    }

    @Override
    public Mono<Long> count() {
        return databaseClient.sql(COUNT_SQL)
                .map(row -> row.get(0, Long.class))
                .one();
    }

    @Override
    public Mono<Optional<WrappedKeyHandle>> findBy(String holderId, String credentialId) {
        return databaseClient.sql(SELECT_SQL)
                .bind("holderId", holderId)
                .bind("credentialId", credentialId)
                .map(this::rowToHandle)
                .one()
                .map(Optional::of)
                .defaultIfEmpty(Optional.empty());
    }

    @Override
    public Mono<Void> insert(WrappedKeyHandle handle) {
        return databaseClient.sql(INSERT_SQL)
                .bind("holderId",     handle.holderId())
                .bind("credentialId", handle.credentialId())
                .bind("wrappedBlob",  handle.wrappedBlob())
                .bind("iv",           handle.iv())
                .bind("tag",          handle.tag())
                .bind("kdfAlgo",      handle.kdfAlgo())
                .bind("kdfVersion",   handle.kdfVersion())
                .bind("cnfJwk",       handle.cnfJwk())
                .bind("createdAt",    handle.createdAt())
                .fetch()
                .rowsUpdated()
                .then()
                .onErrorMap(DataIntegrityViolationException.class, e ->
                        new OnboardingStateException("Concurrent duplicate commit for this credential"));
    }

    private WrappedKeyHandle rowToHandle(Row row, RowMetadata metadata) {
        return new WrappedKeyHandle(
                row.get("holder_id",     String.class),
                row.get("credential_id", String.class),
                row.get("wrapped_blob",  byte[].class),
                row.get("iv",            byte[].class),
                row.get("tag",           byte[].class),
                row.get("kdf_algo",      String.class),
                row.get("kdf_version",   Integer.class),
                row.get("cnf_jwk",       String.class),
                row.get("created_at",    Instant.class),
                row.get("last_used_at",  Instant.class)
        );
    }
}