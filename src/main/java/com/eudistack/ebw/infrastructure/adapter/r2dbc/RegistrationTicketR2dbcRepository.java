package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.RegistrationTicket;
import com.eudistack.ebw.domain.repository.RegistrationTicketRepository;
import io.r2dbc.spi.Readable;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

/** {@code registration_ticket} with {@link DatabaseClient}: single-use consumption is one conditional UPDATE. */
@Repository
public class RegistrationTicketR2dbcRepository implements RegistrationTicketRepository {

    private static final String INSERT_SQL = """
            INSERT INTO registration_ticket (id, user_id, token_hash, expires_at, created_at)
            VALUES (:id, :userId, :tokenHash, :expiresAt, :createdAt)
            """;

    private static final String FIND_USABLE_SQL = """
            SELECT id, user_id, token_hash, expires_at, consumed_at, created_at FROM registration_ticket
             WHERE token_hash = :tokenHash AND consumed_at IS NULL AND expires_at > now()
            """;

    private static final String CONSUME_SQL = """
            UPDATE registration_ticket SET consumed_at = now()
             WHERE id = :id AND consumed_at IS NULL AND expires_at > now()
            """;

    private static final String DELETE_SQL = "DELETE FROM registration_ticket WHERE created_at < :cutoff";

    private final DatabaseClient databaseClient;

    public RegistrationTicketR2dbcRepository(DatabaseClient databaseClient) {
        this.databaseClient = databaseClient;
    }

    @Override
    public Mono<RegistrationTicket> insert(RegistrationTicket ticket) {
        return databaseClient.sql(INSERT_SQL)
                .bind("id", ticket.id())
                .bind("userId", ticket.userId())
                .bind("tokenHash", ticket.tokenHash())
                .bind("expiresAt", ticket.expiresAt())
                .bind("createdAt", ticket.createdAt())
                .fetch().rowsUpdated()
                .thenReturn(ticket);
    }

    @Override
    public Mono<RegistrationTicket> findUsableByTokenHash(String tokenHash) {
        return databaseClient.sql(FIND_USABLE_SQL)
                .bind("tokenHash", tokenHash)
                .map((row, metadata) -> toTicket(row))
                .one();
    }

    @Override
    public Mono<Boolean> consume(UUID id) {
        return databaseClient.sql(CONSUME_SQL).bind("id", id).fetch().rowsUpdated().map(rows -> rows > 0);
    }

    @Override
    public Mono<Long> deleteCreatedBefore(Instant cutoff) {
        return databaseClient.sql(DELETE_SQL).bind("cutoff", cutoff).fetch().rowsUpdated();
    }

    private static RegistrationTicket toTicket(Readable row) {
        return new RegistrationTicket(
                row.get("id", UUID.class),
                row.get("user_id", UUID.class),
                row.get("token_hash", String.class),
                row.get("expires_at", Instant.class),
                row.get("consumed_at", Instant.class),
                row.get("created_at", Instant.class));
    }
}
