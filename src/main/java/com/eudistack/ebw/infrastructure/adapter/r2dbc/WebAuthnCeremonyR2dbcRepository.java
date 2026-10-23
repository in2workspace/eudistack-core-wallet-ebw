package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.CeremonyType;
import com.eudistack.ebw.domain.model.WebAuthnCeremony;
import com.eudistack.ebw.domain.repository.WebAuthnCeremonyRepository;
import io.r2dbc.spi.Readable;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

/** {@code webauthn_ceremony} with {@link DatabaseClient}: the single-use consumption needs {@code RETURNING}. */
@Repository
public class WebAuthnCeremonyR2dbcRepository implements WebAuthnCeremonyRepository {

    private static final String INSERT_SQL = """
            INSERT INTO webauthn_ceremony (id, type, challenge, user_id, expires_at, created_at)
            VALUES (:id, :type, :challenge, :userId, :expiresAt, :createdAt)
            """;

    private static final String CONSUME_SQL = """
            UPDATE webauthn_ceremony SET consumed_at = now()
             WHERE id = :id AND type = :type AND consumed_at IS NULL AND expires_at > now()
            RETURNING id, type, challenge, user_id, expires_at, consumed_at, created_at
            """;

    private static final String DELETE_SQL = "DELETE FROM webauthn_ceremony WHERE created_at < :cutoff";

    private final DatabaseClient databaseClient;

    public WebAuthnCeremonyR2dbcRepository(DatabaseClient databaseClient) {
        this.databaseClient = databaseClient;
    }

    @Override
    public Mono<WebAuthnCeremony> insert(WebAuthnCeremony ceremony) {
        var spec = databaseClient.sql(INSERT_SQL)
                .bind("id", ceremony.id())
                .bind("type", ceremony.type().name())
                .bind("challenge", ceremony.challenge())
                .bind("expiresAt", ceremony.expiresAt())
                .bind("createdAt", ceremony.createdAt());
        spec = ceremony.userId() == null ? spec.bindNull("userId", UUID.class) : spec.bind("userId", ceremony.userId());
        return spec.fetch().rowsUpdated().thenReturn(ceremony);
    }

    @Override
    public Mono<WebAuthnCeremony> consume(UUID id, CeremonyType type) {
        return databaseClient.sql(CONSUME_SQL)
                .bind("id", id)
                .bind("type", type.name())
                .map((row, metadata) -> toCeremony(row))
                .one();
    }

    @Override
    public Mono<Long> deleteCreatedBefore(Instant cutoff) {
        return databaseClient.sql(DELETE_SQL).bind("cutoff", cutoff).fetch().rowsUpdated();
    }

    private static WebAuthnCeremony toCeremony(Readable row) {
        return new WebAuthnCeremony(
                row.get("id", UUID.class),
                CeremonyType.valueOf(row.get("type", String.class)),
                row.get("challenge", byte[].class),
                row.get("user_id", UUID.class),
                row.get("expires_at", Instant.class),
                row.get("consumed_at", Instant.class),
                row.get("created_at", Instant.class));
    }
}
