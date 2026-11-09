package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.RegistrationTicket;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.DatabaseClientStub;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link RegistrationTicketR2dbcRepository}: bindings and row mapping. The SQL itself runs
 * against PostgreSQL in the integration tests.
 */
class RegistrationTicketR2dbcRepositoryTest {

    private static final UUID USER_ID = UUID.randomUUID();
    private static final UUID PREREGISTRATION_ID = UUID.randomUUID();

    private DatabaseClientStub db;
    private RegistrationTicketR2dbcRepository repository;

    @BeforeEach
    void setUp() {
        db = new DatabaseClientStub();
        repository = new RegistrationTicketR2dbcRepository(db.client);
    }

    @Test
    void insert_ticketOfAccount_bindsThePreregistrationAsNull() {
        // Arrange
        var ticket = RegistrationTicket.issue(USER_ID, "hash");

        // Act & Assert
        StepVerifier.create(repository.insert(ticket)).expectNext(ticket).verifyComplete();
        assertThat(db.bindings)
                .containsEntry("id", ticket.id())
                .containsEntry("userId", USER_ID)
                .containsEntry("preregistrationId", null)
                .containsEntry("tokenHash", "hash")
                .containsEntry("expiresAt", ticket.expiresAt())
                .containsEntry("createdAt", ticket.createdAt());
    }

    @Test
    void insert_ticketOfPreregistrationWithoutAccount_bindsTheAccountAsNull() {
        // Arrange
        var ticket = RegistrationTicket.issueForPreregistration(null, PREREGISTRATION_ID, "hash");

        // Act & Assert
        StepVerifier.create(repository.insert(ticket)).expectNext(ticket).verifyComplete();
        assertThat(db.bindings)
                .containsEntry("userId", null)
                .containsEntry("preregistrationId", PREREGISTRATION_ID);
    }

    @Test
    void findUsableByTokenHash_usableTicket_mapsTheRow() {
        // Arrange
        var id = UUID.randomUUID();
        var expiresAt = Instant.parse("2026-11-09T10:05:00Z");
        var createdAt = Instant.parse("2026-11-09T10:00:00Z");
        when(db.row.get("id", UUID.class)).thenReturn(id);
        when(db.row.get("user_id", UUID.class)).thenReturn(USER_ID);
        when(db.row.get("preregistration_id", UUID.class)).thenReturn(PREREGISTRATION_ID);
        when(db.row.get("token_hash", String.class)).thenReturn("hash");
        when(db.row.get("expires_at", Instant.class)).thenReturn(expiresAt);
        when(db.row.get("created_at", Instant.class)).thenReturn(createdAt);

        // Act & Assert
        StepVerifier.create(repository.findUsableByTokenHash("hash"))
                .expectNext(new RegistrationTicket(id, USER_ID, PREREGISTRATION_ID, "hash", expiresAt, null,
                        createdAt))
                .verifyComplete();
        assertThat(db.bindings).containsEntry("tokenHash", "hash");
    }
}
