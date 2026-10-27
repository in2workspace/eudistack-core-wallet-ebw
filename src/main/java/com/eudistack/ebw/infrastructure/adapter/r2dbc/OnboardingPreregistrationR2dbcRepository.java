package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.ExpiredPreregistration;
import com.eudistack.ebw.domain.model.OnboardingPreregistration;
import com.eudistack.ebw.domain.repository.OnboardingPreregistrationRepository;
import io.r2dbc.spi.Readable;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

/** {@code onboarding_preregistration} with {@link DatabaseClient}: the single-use redemption needs {@code RETURNING}. */
@Repository
public class OnboardingPreregistrationR2dbcRepository implements OnboardingPreregistrationRepository {

    private static final String COLUMNS = "id, token_hash, email, credential_offer, requested_by, "
            + "webauthn_user_handle, expires_at, redeemed_at, created_at";

    private static final String INSERT_SQL = """
            INSERT INTO onboarding_preregistration (id, token_hash, email, credential_offer, requested_by,
                                                    expires_at, created_at)
            VALUES (:id, :tokenHash, :email, :credentialOffer, :requestedBy, :expiresAt, :createdAt)
            """;

    private static final String REDEEM_SQL = "UPDATE onboarding_preregistration SET redeemed_at = now()"
            + " WHERE token_hash = :tokenHash AND redeemed_at IS NULL AND expires_at > now()"
            + " RETURNING " + COLUMNS;

    private static final String ASSIGN_HANDLE_SQL =
            "UPDATE onboarding_preregistration SET webauthn_user_handle = :handle WHERE id = :id";

    private static final String FIND_SQL = "SELECT " + COLUMNS + " FROM onboarding_preregistration WHERE id = :id";

    private static final String DELETE_SQL = "DELETE FROM onboarding_preregistration WHERE id = :id";

    private static final String DELETE_EXPIRED_SQL = """
            DELETE FROM onboarding_preregistration WHERE expires_at <= now()
            RETURNING id, requested_by, redeemed_at
            """;

    private final DatabaseClient databaseClient;

    public OnboardingPreregistrationR2dbcRepository(DatabaseClient databaseClient) {
        this.databaseClient = databaseClient;
    }

    @Override
    public Mono<OnboardingPreregistration> insert(OnboardingPreregistration preregistration) {
        var spec = databaseClient.sql(INSERT_SQL)
                .bind("id", preregistration.id())
                .bind("tokenHash", preregistration.tokenHash())
                .bind("email", preregistration.email())
                .bind("requestedBy", preregistration.requestedBy())
                .bind("expiresAt", preregistration.expiresAt())
                .bind("createdAt", preregistration.createdAt());
        spec = preregistration.credentialOffer() == null
                ? spec.bindNull("credentialOffer", String.class)
                : spec.bind("credentialOffer", preregistration.credentialOffer());
        return spec.fetch().rowsUpdated().thenReturn(preregistration);
    }

    @Override
    public Mono<OnboardingPreregistration> redeem(String tokenHash) {
        return databaseClient.sql(REDEEM_SQL)
                .bind("tokenHash", tokenHash)
                .map((row, metadata) -> toPreregistration(row))
                .one();
    }

    @Override
    public Mono<Void> assignUserHandle(UUID id, byte[] webauthnUserHandle) {
        return databaseClient.sql(ASSIGN_HANDLE_SQL)
                .bind("id", id)
                .bind("handle", webauthnUserHandle)
                .fetch().rowsUpdated()
                .then();
    }

    @Override
    public Mono<OnboardingPreregistration> findById(UUID id) {
        return databaseClient.sql(FIND_SQL)
                .bind("id", id)
                .map((row, metadata) -> toPreregistration(row))
                .one();
    }

    @Override
    public Mono<Boolean> deleteById(UUID id) {
        return databaseClient.sql(DELETE_SQL).bind("id", id).fetch().rowsUpdated().map(rows -> rows > 0);
    }

    @Override
    public Flux<ExpiredPreregistration> deleteExpired() {
        return databaseClient.sql(DELETE_EXPIRED_SQL)
                .map((row, metadata) -> new ExpiredPreregistration(
                        row.get("id", UUID.class),
                        row.get("requested_by", String.class),
                        row.get("redeemed_at", Instant.class) != null))
                .all();
    }

    private static OnboardingPreregistration toPreregistration(Readable row) {
        return new OnboardingPreregistration(
                row.get("id", UUID.class),
                row.get("token_hash", String.class),
                row.get("email", String.class),
                row.get("credential_offer", String.class),
                row.get("requested_by", String.class),
                row.get("webauthn_user_handle", byte[].class),
                row.get("expires_at", Instant.class),
                row.get("redeemed_at", Instant.class),
                row.get("created_at", Instant.class));
    }
}
