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

    private static final String DELETE_SQL =
            "DELETE FROM onboarding_disavowal WHERE consumed_at IS NOT NULL OR expires_at <= now()";

    private final DatabaseClient databaseClient;

    public OnboardingDisavowalR2dbcRepository(DatabaseClient databaseClient) {
        this.databaseClient = databaseClient;
    }

    @Override
    public Mono<OnboardingDisavowal> insert(OnboardingDisavowal disavowal) {
        var spec = databaseClient.sql(INSERT_SQL)
                .bind("id", disavowal.id())
                .bind("tokenHash", disavowal.tokenHash())
                .bind("userId", disavowal.userId())
                .bind("requestedBy", disavowal.requestedBy())
                .bind("registeredAt", disavowal.registeredAt())
                .bind("expiresAt", disavowal.expiresAt())
                .bind("createdAt", disavowal.createdAt());
        spec = disavowal.passkeyId() == null
                ? spec.bindNull("passkeyId", UUID.class)
                : spec.bind("passkeyId", disavowal.passkeyId());
        return spec.fetch().rowsUpdated().thenReturn(disavowal);
    }

    @Override
    public Mono<OnboardingDisavowal> consume(String tokenHash) {
        return databaseClient.sql(CONSUME_SQL)
                .bind("tokenHash", tokenHash)
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
