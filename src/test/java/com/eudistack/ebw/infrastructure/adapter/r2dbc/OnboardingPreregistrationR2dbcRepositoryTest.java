package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.ExpiredPreregistration;
import com.eudistack.ebw.domain.model.OnboardingPreregistration;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.DatabaseClientStub;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OnboardingPreregistrationR2dbcRepository}: bindings and row mapping. The SQL itself
 * (single-use redemption, expiry) runs against PostgreSQL in {@code OnboardingRepositoriesIT}.
 */
class OnboardingPreregistrationR2dbcRepositoryTest {

    private static final UUID ID = UUID.randomUUID();
    private static final byte[] HANDLE = {1, 2, 3};
    private static final Instant EXPIRES_AT = Instant.parse("2026-11-10T10:00:00Z");
    private static final Instant REDEEMED_AT = Instant.parse("2026-11-09T10:05:00Z");
    private static final Instant CREATED_AT = Instant.parse("2026-11-09T10:00:00Z");

    private DatabaseClientStub db;
    private OnboardingPreregistrationR2dbcRepository repository;

    @BeforeEach
    void setUp() {
        db = new DatabaseClientStub();
        repository = new OnboardingPreregistrationR2dbcRepository(db.client);
    }

    private void stubRow() {
        when(db.row.get("id", UUID.class)).thenReturn(ID);
        when(db.row.get("token_hash", String.class)).thenReturn("hash");
        when(db.row.get("email", String.class)).thenReturn("user@example.com");
        when(db.row.get("credential_offer", String.class)).thenReturn("offer");
        when(db.row.get("requested_by", String.class)).thenReturn("verifier");
        when(db.row.get("webauthn_user_handle", byte[].class)).thenReturn(HANDLE);
        when(db.row.get("expires_at", Instant.class)).thenReturn(EXPIRES_AT);
        when(db.row.get("redeemed_at", Instant.class)).thenReturn(REDEEMED_AT);
        when(db.row.get("created_at", Instant.class)).thenReturn(CREATED_AT);
    }

    private static OnboardingPreregistration expected() {
        return new OnboardingPreregistration(ID, "hash", "user@example.com", "offer", "verifier", HANDLE, EXPIRES_AT,
                REDEEMED_AT, CREATED_AT);
    }

    @Test
    void insert_withOffer_bindsEveryColumnAndEmitsThePreregistration() {
        // Arrange
        var preregistration = OnboardingPreregistration.create("hash", "user@example.com", "offer", "verifier",
                Duration.ofHours(1));

        // Act & Assert
        StepVerifier.create(repository.insert(preregistration)).expectNext(preregistration).verifyComplete();
        assertThat(db.executedSql.getFirst()).contains("INSERT INTO onboarding_preregistration");
        assertThat(db.bindings)
                .containsEntry("id", preregistration.id())
                .containsEntry("tokenHash", "hash")
                .containsEntry("email", "user@example.com")
                .containsEntry("credentialOffer", "offer")
                .containsEntry("requestedBy", "verifier")
                .containsEntry("expiresAt", preregistration.expiresAt())
                .containsEntry("createdAt", preregistration.createdAt());
    }

    @Test
    void insert_withoutOffer_bindsTheOfferAsNull() {
        // Arrange
        var preregistration = OnboardingPreregistration.create("hash", "user@example.com", null, "verifier",
                Duration.ofHours(1));

        // Act & Assert
        StepVerifier.create(repository.insert(preregistration)).expectNext(preregistration).verifyComplete();
        assertThat(db.bindings).containsEntry("credentialOffer", null);
    }

    @Test
    void redeem_usableTicket_bindsTheHashAndMapsTheRow() {
        // Arrange
        stubRow();

        // Act & Assert
        StepVerifier.create(repository.redeem("hash")).expectNext(expected()).verifyComplete();
        assertThat(db.executedSql.getFirst()).startsWith("UPDATE onboarding_preregistration SET redeemed_at");
        assertThat(db.bindings).containsEntry("tokenHash", "hash");
    }

    @Test
    void redeem_noUsableTicket_completesEmpty() {
        // Arrange
        db.rowPresent = false;

        // Act & Assert
        StepVerifier.create(repository.redeem("hash")).verifyComplete();
    }

    @Test
    void assignUserHandle_bindsIdAndHandle() {
        // Act & Assert
        StepVerifier.create(repository.assignUserHandle(ID, HANDLE)).verifyComplete();
        assertThat(db.executedSql.getFirst()).contains("SET webauthn_user_handle");
        assertThat(db.bindings).containsEntry("id", ID).containsEntry("handle", HANDLE);
    }

    @Test
    void keepUntil_bindsIdAndInstant() {
        // Act & Assert
        StepVerifier.create(repository.keepUntil(ID, EXPIRES_AT)).verifyComplete();
        assertThat(db.executedSql.getFirst()).contains("GREATEST(expires_at, :until)");
        assertThat(db.bindings).containsEntry("id", ID).containsEntry("until", EXPIRES_AT);
    }

    @Test
    void findById_existingRow_mapsIt() {
        // Arrange
        stubRow();

        // Act & Assert
        StepVerifier.create(repository.findById(ID)).expectNext(expected()).verifyComplete();
        assertThat(db.bindings).containsEntry("id", ID);
    }

    @Test
    void deleteById_rowDeleted_emitsTrue() {
        // Act & Assert
        StepVerifier.create(repository.deleteById(ID)).expectNext(true).verifyComplete();
        assertThat(db.bindings).containsEntry("id", ID);
    }

    @Test
    void deleteById_noRow_emitsFalse() {
        // Arrange
        db.rowsUpdated = Mono.just(0L);

        // Act & Assert
        StepVerifier.create(repository.deleteById(ID)).expectNext(false).verifyComplete();
    }

    @Test
    void deleteExpired_redeemedRow_mapsItAsRedeemed() {
        // Arrange
        when(db.row.get("id", UUID.class)).thenReturn(ID);
        when(db.row.get("requested_by", String.class)).thenReturn("verifier");
        when(db.row.get("redeemed_at", Instant.class)).thenReturn(REDEEMED_AT);

        // Act & Assert
        StepVerifier.create(repository.deleteExpired())
                .expectNext(new ExpiredPreregistration(ID, "verifier", true))
                .verifyComplete();
        assertThat(db.executedSql.getFirst()).contains("DELETE FROM onboarding_preregistration");
    }

    @Test
    void deleteExpired_notRedeemedRow_mapsItAsNotRedeemed() {
        // Arrange
        when(db.row.get("id", UUID.class)).thenReturn(ID);
        when(db.row.get("requested_by", String.class)).thenReturn("verifier");

        // Act & Assert
        StepVerifier.create(repository.deleteExpired())
                .expectNext(new ExpiredPreregistration(ID, "verifier", false))
                .verifyComplete();
    }
}
