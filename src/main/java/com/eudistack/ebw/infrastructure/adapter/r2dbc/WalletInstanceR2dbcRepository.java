package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.WalletInstance;
import com.eudistack.ebw.domain.model.WalletInstance.DeviceType;
import com.eudistack.ebw.domain.model.WalletInstance.RevokedBy;
import com.eudistack.ebw.domain.model.WalletInstance.Status;
import com.eudistack.ebw.domain.repository.WalletInstanceRepository;
import io.r2dbc.spi.Readable;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

/**
 * {@code wallet_instance} with {@link DatabaseClient}: every state change is a conditional {@code UPDATE ...
 * RETURNING}, so a revocation and a binding of the same instance never overwrite each other (EUD-15 design §7).
 */
@Repository
public class WalletInstanceR2dbcRepository implements WalletInstanceRepository {

    private static final String COLUMNS = "id, user_id, display_name, device_type, status, created_at, last_used_at,"
            + " revoked_at, revoked_by, registered_passkey_id";

    private static final String INSERT_SQL = """
            INSERT INTO wallet_instance (id, user_id, display_name, device_type, status, created_at, last_used_at,
                                         registered_passkey_id)
            VALUES (:id, :userId, :displayName, :deviceType, :status, :createdAt, :lastUsedAt, :registeredPasskeyId)
            """;

    private static final String FIND_SQL = "SELECT " + COLUMNS
            + " FROM wallet_instance WHERE id = :id AND user_id = :userId";

    private static final String FIND_ACTIVE_SQL = "SELECT " + COLUMNS
            + " FROM wallet_instance WHERE user_id = :userId AND status = 'ACTIVE'";

    private static final String COUNT_SQL = "SELECT count(*) AS total FROM wallet_instance WHERE user_id = :userId";

    private static final String TOUCH_SQL = "UPDATE wallet_instance SET last_used_at = now()"
            + " WHERE id = :id AND user_id = :userId AND status = 'ACTIVE' RETURNING " + COLUMNS;

    private static final String RENAME_SQL = "UPDATE wallet_instance SET display_name = :displayName"
            + " WHERE id = :id AND user_id = :userId AND status = 'ACTIVE' RETURNING " + COLUMNS;

    private static final String REVOKE_SQL = "UPDATE wallet_instance"
            + " SET status = 'REVOKED', revoked_at = now(), revoked_by = :revokedBy"
            + " WHERE id = :id AND status = 'ACTIVE'";

    private static final String REVOKE_BY_PASSKEY_SQL = "UPDATE wallet_instance"
            + " SET status = 'REVOKED', revoked_at = now(), revoked_by = :revokedBy"
            + " WHERE registered_passkey_id = :passkeyId AND status = 'ACTIVE' RETURNING id";

    /** Batches of the oldest first; the status is re-checked on the locked rows (design §2.1). */
    private static final String REVOKE_INACTIVE_SQL = """
            UPDATE wallet_instance SET status = 'REVOKED', revoked_at = now(), revoked_by = 'INACTIVITY'
             WHERE status = 'ACTIVE'
               AND id IN (SELECT id FROM wallet_instance
                           WHERE status = 'ACTIVE' AND coalesce(last_used_at, created_at) < :cutoff
                           ORDER BY coalesce(last_used_at, created_at)
                           LIMIT :limit
                           FOR UPDATE SKIP LOCKED)
            RETURNING\s""" + COLUMNS;

    private static final String ID = "id";
    private static final String USER_ID = "userId";
    private static final String REVOKED_BY = "revokedBy";

    private final DatabaseClient databaseClient;

    public WalletInstanceR2dbcRepository(DatabaseClient databaseClient) {
        this.databaseClient = databaseClient;
    }

    @Override
    public Mono<WalletInstance> insert(WalletInstance instance) {
        var spec = databaseClient.sql(INSERT_SQL)
                .bind(ID, instance.id())
                .bind(USER_ID, instance.userId())
                .bind("displayName", instance.displayName())
                .bind("deviceType", instance.deviceType().name())
                .bind("status", instance.status().name())
                .bind("createdAt", instance.createdAt())
                .bind("registeredPasskeyId", instance.registeredPasskeyId());
        spec = instance.lastUsedAt() == null
                ? spec.bindNull("lastUsedAt", Instant.class)
                : spec.bind("lastUsedAt", instance.lastUsedAt());
        return spec.fetch().rowsUpdated().thenReturn(instance);
    }

    @Override
    public Mono<WalletInstance> findByIdAndUserId(UUID id, UUID userId) {
        return databaseClient.sql(FIND_SQL).bind(ID, id).bind(USER_ID, userId)
                .map((row, metadata) -> toInstance(row))
                .one();
    }

    @Override
    public Flux<WalletInstance> findActiveByUserId(UUID userId) {
        return databaseClient.sql(FIND_ACTIVE_SQL).bind(USER_ID, userId)
                .map((row, metadata) -> toInstance(row))
                .all();
    }

    @Override
    public Mono<Long> countByUserId(UUID userId) {
        return databaseClient.sql(COUNT_SQL).bind(USER_ID, userId)
                .map((row, metadata) -> row.get("total", Long.class))
                .one()
                .defaultIfEmpty(0L);
    }

    @Override
    public Mono<WalletInstance> touchIfActive(UUID id, UUID userId) {
        return databaseClient.sql(TOUCH_SQL).bind(ID, id).bind(USER_ID, userId)
                .map((row, metadata) -> toInstance(row))
                .one();
    }

    @Override
    public Mono<WalletInstance> renameIfActive(UUID id, UUID userId, String displayName) {
        return databaseClient.sql(RENAME_SQL).bind(ID, id).bind(USER_ID, userId).bind("displayName", displayName)
                .map((row, metadata) -> toInstance(row))
                .one();
    }

    @Override
    public Mono<Boolean> revokeIfActive(UUID id, RevokedBy revokedBy) {
        return databaseClient.sql(REVOKE_SQL).bind(ID, id).bind(REVOKED_BY, revokedBy.name())
                .fetch().rowsUpdated()
                .map(rows -> rows > 0)
                .defaultIfEmpty(false);
    }

    @Override
    public Flux<UUID> revokeActiveByRegisteredPasskey(UUID passkeyId, RevokedBy revokedBy) {
        return databaseClient.sql(REVOKE_BY_PASSKEY_SQL).bind("passkeyId", passkeyId)
                .bind(REVOKED_BY, revokedBy.name())
                .map((row, metadata) -> row.get(ID, UUID.class))
                .all();
    }

    @Override
    public Flux<WalletInstance> revokeInactiveBatch(Instant cutoff, int limit) {
        return databaseClient.sql(REVOKE_INACTIVE_SQL).bind("cutoff", cutoff).bind("limit", limit)
                .map((row, metadata) -> toInstance(row))
                .all();
    }

    private static WalletInstance toInstance(Readable row) {
        var revokedBy = row.get("revoked_by", String.class);
        return new WalletInstance(
                row.get(ID, UUID.class),
                row.get("user_id", UUID.class),
                row.get("display_name", String.class),
                DeviceType.valueOf(row.get("device_type", String.class)),
                Status.valueOf(row.get("status", String.class)),
                row.get("created_at", Instant.class),
                row.get("last_used_at", Instant.class),
                row.get("revoked_at", Instant.class),
                revokedBy == null ? null : RevokedBy.valueOf(revokedBy),
                row.get("registered_passkey_id", UUID.class));
    }
}
