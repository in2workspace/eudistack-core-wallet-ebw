package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.OnboardingDisavowal;
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
 * Unit tests for {@link OnboardingDisavowalR2dbcRepository}: bindings and row mapping. The SQL itself
 * (single-use consumption, cleanup) runs against PostgreSQL in {@code OnboardingRepositoriesIT}.
 */
class OnboardingDisavowalR2dbcRepositoryTest {

    private static final UUID ID = UUID.randomUUID();
    private static final UUID USER_ID = UUID.randomUUID();
    private static final UUID PASSKEY_ID = UUID.randomUUID();
    private static final Instant REGISTERED_AT = Instant.parse("2026-11-09T10:00:00Z");
    private static final Instant EXPIRES_AT = Instant.parse("2026-11-16T10:00:00Z");
    private static final Instant CONSUMED_AT = Instant.parse("2026-11-09T11:00:00Z");
    private static final Instant CREATED_AT = Instant.parse("2026-11-09T10:00:01Z");

    private DatabaseClientStub db;
    private OnboardingDisavowalR2dbcRepository repository;

    @BeforeEach
    void setUp() {
        db = new DatabaseClientStub();
        repository = new OnboardingDisavowalR2dbcRepository(db.client);
    }

    private void stubRow() {
        when(db.row.get("id", UUID.class)).thenReturn(ID);
        when(db.row.get("token_hash", String.class)).thenReturn("hash");
        when(db.row.get("user_id", UUID.class)).thenReturn(USER_ID);
        when(db.row.get("passkey_id", UUID.class)).thenReturn(PASSKEY_ID);
        when(db.row.get("requested_by", String.class)).thenReturn("verifier");
        when(db.row.get("registered_at", Instant.class)).thenReturn(REGISTERED_AT);
        when(db.row.get("account_created", Boolean.class)).thenReturn(true);
        when(db.row.get("expires_at", Instant.class)).thenReturn(EXPIRES_AT);
        when(db.row.get("consumed_at", Instant.class)).thenReturn(CONSUMED_AT);
        when(db.row.get("created_at", Instant.class)).thenReturn(CREATED_AT);
    }

    private static OnboardingDisavowal expected() {
        return new OnboardingDisavowal(ID, "hash", USER_ID, PASSKEY_ID, "verifier", REGISTERED_AT, true,
                EXPIRES_AT, CONSUMED_AT, CREATED_AT);
    }

    @Test
    void insert_issuedDisavowal_bindsEveryColumnAndEmitsIt() {
        // Arrange
        var disavowal = OnboardingDisavowal.issue("hash", USER_ID, PASSKEY_ID, "verifier", REGISTERED_AT, true);

        // Act & Assert
        StepVerifier.create(repository.insert(disavowal)).expectNext(disavowal).verifyComplete();
        assertThat(db.executedSql.getFirst()).contains("INSERT INTO onboarding_disavowal");
        assertThat(db.bindings)
                .containsEntry("id", disavowal.id())
                .containsEntry("tokenHash", "hash")
                .containsEntry("userId", USER_ID)
                .containsEntry("passkeyId", PASSKEY_ID)
                .containsEntry("requestedBy", "verifier")
                .containsEntry("registeredAt", REGISTERED_AT)
                .containsEntry("accountCreated", true)
                .containsEntry("expiresAt", disavowal.expiresAt())
                .containsEntry("createdAt", disavowal.createdAt());
    }

    @Test
    void insert_pendingDisavowalWithoutPasskey_bindsTheMissingColumnsAsNull() {
        // Arrange
        var disavowal = OnboardingDisavowal.pending(USER_ID, null, "verifier", REGISTERED_AT, false);

        // Act & Assert
        StepVerifier.create(repository.insert(disavowal)).expectNext(disavowal).verifyComplete();
        assertThat(db.bindings)
                .containsEntry("accountCreated", false)
                .containsEntry("tokenHash", null)
                .containsEntry("expiresAt", null)
                .containsEntry("passkeyId", null);
    }

    @Test
    void consume_usableToken_bindsTheHashAndMapsTheRow() {
        // Arrange
        stubRow();

        // Act & Assert
        StepVerifier.create(repository.consume("hash")).expectNext(expected()).verifyComplete();
        assertThat(db.executedSql.getFirst()).contains("SET consumed_at = now()");
        assertThat(db.bindings).containsEntry("tokenHash", "hash");
    }

    @Test
    void consume_noUsableToken_completesEmpty() {
        // Arrange
        db.rowPresent = false;

        // Act & Assert
        StepVerifier.create(repository.consume("hash")).verifyComplete();
    }

    @Test
    void assignToken_pendingRow_bindsPasskeyHashAndExpiryAndMapsTheRow() {
        // Arrange
        stubRow();

        // Act & Assert
        StepVerifier.create(repository.assignToken(PASSKEY_ID, "hash", EXPIRES_AT))
                .expectNext(expected())
                .verifyComplete();
        assertThat(db.executedSql.getFirst()).contains("SET token_hash = :tokenHash");
        assertThat(db.bindings)
                .containsEntry("passkeyId", PASSKEY_ID)
                .containsEntry("tokenHash", "hash")
                .containsEntry("expiresAt", EXPIRES_AT);
    }

    @Test
    void deleteConsumedOrExpired_emitsTheDeletedRows() {
        // Arrange
        db.rowsUpdated = Mono.just(3L);

        // Act & Assert
        StepVerifier.create(repository.deleteConsumedOrExpired()).expectNext(3L).verifyComplete();
        assertThat(db.executedSql.getFirst()).startsWith("DELETE FROM onboarding_disavowal");
    }
}
