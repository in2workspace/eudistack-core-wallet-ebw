package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.OnboardingDisavowal;
import com.eudistack.ebw.domain.repository.OnboardingDisavowalRepository;
import io.r2dbc.spi.Readable;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

/** {@code onboarding_disavowal} with {@link DatabaseClient}: the single-use consumption needs {@code RETURNING}. */
@Repository
public class OnboardingDisavowalR2dbcRepository implements OnboardingDisavowalRepository {

    private static final String TOKEN_HASH = "tokenHash";
    private static final String EXPIRES_AT = "expiresAt";
    private static final String PASSKEY_ID = "passkeyId";

    private static final String INSERT_SQL = """
            INSERT INTO onboarding_disavowal (id, token_hash, user_id, passkey_id, requested_by, registered_at,
                                              expires_at, created_at)
            VALUES (:id, :tokenHash, :userId, :passkeyId, :requestedBy, :registeredAt, :expiresAt, :createdAt)
            """;

    private static final String CONSUME_SQL = """
            UPDATE onboarding_disavowal SET consumed_at = now()
             WHERE token_hash = :tokenHash AND consumed_at IS NULL AND expires_at > now()
            RETURNING id, token_hash, user_id, passkey_id, requested_by, registered_at, expires_at, consumed_at,
                      created_at
            """;

    private static final String ASSIGN_TOKEN_SQL = """
            UPDATE onboarding_disavowal SET token_hash = :tokenHash, expires_at = :expiresAt
             WHERE passkey_id = :passkeyId AND token_hash IS NULL
            RETURNING id, token_hash, user_id, passkey_id, requested_by, registered_at, expires_at, consumed_at,
                      created_at
            """;

    /** Also the rows whose email was never sent, once they could no longer be used anyway. */
    private static final String DELETE_SQL = "DELETE FROM onboarding_disavowal WHERE consumed_at IS NOT NULL"
            + " OR expires_at <= now() OR (token_hash IS NULL AND created_at < now() - interval '7 days')";

    private final DatabaseClient databaseClient;

    public OnboardingDisavowalR2dbcRepository(DatabaseClient databaseClient) {
        this.databaseClient = databaseClient;
    }

    @Override
    public Mono<OnboardingDisavowal> insert(OnboardingDisavowal disavowal) {
        var spec = databaseClient.sql(INSERT_SQL)
                .bind("id", disavowal.id())
                .bind("userId", disavowal.userId())
                .bind("requestedBy", disavowal.requestedBy())
                .bind("registeredAt", disavowal.registeredAt())
                .bind("createdAt", disavowal.createdAt());
        spec = disavowal.tokenHash() == null
                ? spec.bindNull(TOKEN_HASH, String.class)
                : spec.bind(TOKEN_HASH, disavowal.tokenHash());
        spec = disavowal.expiresAt() == null
                ? spec.bindNull(EXPIRES_AT, Instant.class)
                : spec.bind(EXPIRES_AT, disavowal.expiresAt());
        spec = disavowal.passkeyId() == null
                ? spec.bindNull(PASSKEY_ID, UUID.class)
                : spec.bind(PASSKEY_ID, disavowal.passkeyId());
        return spec.fetch().rowsUpdated().thenReturn(disavowal);
    }

    @Override
    public Mono<OnboardingDisavowal> consume(String tokenHash) {
        return databaseClient.sql(CONSUME_SQL)
                .bind(TOKEN_HASH, tokenHash)
                .map((row, metadata) -> toDisavowal(row))
                .one();
    }

    @Override
    public Mono<OnboardingDisavowal> assignToken(UUID passkeyId, String tokenHash, Instant expiresAt) {
        return databaseClient.sql(ASSIGN_TOKEN_SQL)
                .bind(PASSKEY_ID, passkeyId)
                .bind(TOKEN_HASH, tokenHash)
                .bind(EXPIRES_AT, expiresAt)
                .map((row, metadata) -> toDisavowal(row))
                .one();
    }

    @Override
    public Mono<Long> deleteConsumedOrExpired() {
        return databaseClient.sql(DELETE_SQL).fetch().rowsUpdated();
    }

    private static OnboardingDisavowal toDisavowal(Readable row) {
        return new OnboardingDisavowal(
                row.get("id", UUID.class),
                row.get("token_hash", String.class),
                row.get("user_id", UUID.class),
                row.get("passkey_id", UUID.class),
                row.get("requested_by", String.class),
                row.get("registered_at", Instant.class),
                row.get("expires_at", Instant.class),
                row.get("consumed_at", Instant.class),
                row.get("created_at", Instant.class));
    }
}
