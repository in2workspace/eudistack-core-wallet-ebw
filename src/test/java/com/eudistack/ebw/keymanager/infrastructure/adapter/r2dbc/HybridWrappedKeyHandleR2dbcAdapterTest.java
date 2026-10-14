package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.keymanager.domain.exception.OnboardingStateException;
import com.eudistack.ebw.keymanager.domain.model.WrappedKeyHandle;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link HybridWrappedKeyHandleR2dbcAdapter} — raw SQL over the composite-key table: counts, the
 * row → {@link WrappedKeyHandle} mapping and the duplicate-commit translation. Schema and constraints are covered
 * by the {@code HybridWrappedKeyHandle*IT} suites.
 */
class HybridWrappedKeyHandleR2dbcAdapterTest {

    private static final String HOLDER_ID = UUID.randomUUID().toString();
    private static final String CREDENTIAL_ID = "cred-1";
    private static final Instant CREATED_AT = Instant.parse("2026-05-26T10:00:00Z");

    private DatabaseClientStub db;
    private HybridWrappedKeyHandleR2dbcAdapter adapter;

    @BeforeEach
    void setUp() {
        db = new DatabaseClientStub();
        adapter = new HybridWrappedKeyHandleR2dbcAdapter(db.client);
    }

    @Test
    void count_returnsTheFirstColumn() {
        // Arrange
        when(db.row.get(0, Long.class)).thenReturn(7L);

        // Act + Assert
        StepVerifier.create(adapter.count()).expectNext(7L).verifyComplete();
        assertThat(db.executedSql.get(0)).isEqualTo("SELECT COUNT(*) FROM hybrid_wrapped_key_handle");
    }

    @Test
    void countOrphaned_joinsAgainstThePrfSaltTable() {
        // Arrange
        when(db.row.get(0, Long.class)).thenReturn(0L);

        // Act + Assert
        StepVerifier.create(adapter.countOrphaned()).expectNext(0L).verifyComplete();
        assertThat(db.executedSql.get(0)).contains("LEFT JOIN hybrid_prf_salt");
    }

    @Test
    void findBy_existingRow_mapsEveryColumn() {
        // Arrange
        var lastUsed = CREATED_AT.plusSeconds(30);
        when(db.row.get("holder_id", UUID.class)).thenReturn(UUID.fromString(HOLDER_ID));
        when(db.row.get("credential_id", String.class)).thenReturn(CREDENTIAL_ID);
        when(db.row.get("wrapped_blob", byte[].class)).thenReturn(new byte[48]);
        when(db.row.get("iv", byte[].class)).thenReturn(new byte[12]);
        when(db.row.get("tag", byte[].class)).thenReturn(new byte[16]);
        when(db.row.get("kdf_algo", String.class)).thenReturn("HKDF-SHA256");
        when(db.row.get("kdf_version", Integer.class)).thenReturn(1);
        when(db.row.get("cnf_jwk", String.class)).thenReturn("{\"kty\":\"EC\"}");
        when(db.row.get("created_at", Instant.class)).thenReturn(CREATED_AT);
        when(db.row.get("last_used_at", Instant.class)).thenReturn(lastUsed);

        // Act
        var result = adapter.findBy(HOLDER_ID, CREDENTIAL_ID);

        // Assert
        StepVerifier.create(result)
                .assertNext(found -> {
                    assertThat(found).isPresent();
                    assertThat(found.get().holderId()).isEqualTo(HOLDER_ID);
                    assertThat(found.get().kdfVersion()).isEqualTo(1);
                    assertThat(found.get().lastUsedAt()).isEqualTo(lastUsed);
                })
                .verifyComplete();
        assertThat(db.bindings)
                .containsEntry("holderId", UUID.fromString(HOLDER_ID))
                .containsEntry("credentialId", CREDENTIAL_ID);
    }

    @Test
    void findBy_noRow_returnsEmptyOptional() {
        // Arrange
        db.rowPresent = false;

        // Act + Assert
        StepVerifier.create(adapter.findBy(HOLDER_ID, CREDENTIAL_ID))
                .expectNext(Optional.empty())
                .verifyComplete();
    }

    @Test
    void insert_newHandle_bindsEveryColumn() {
        // Arrange
        var handle = handle();

        // Act
        var result = adapter.insert(handle);

        // Assert
        StepVerifier.create(result).verifyComplete();
        assertThat(db.executedSql.get(0)).startsWith("INSERT INTO hybrid_wrapped_key_handle");
        assertThat(db.bindings)
                .containsEntry("holderId", UUID.fromString(HOLDER_ID))
                .containsEntry("credentialId", CREDENTIAL_ID)
                .containsEntry("kdfAlgo", "HKDF-SHA256")
                .containsEntry("kdfVersion", 1)
                .containsEntry("cnfJwk", "{\"kty\":\"EC\"}")
                .containsEntry("createdAt", CREATED_AT)
                .containsKeys("wrappedBlob", "iv", "tag");
    }

    @Test
    void insert_duplicateCommit_isTranslatedToOnboardingStateException() {
        // Arrange
        db.rowsUpdated = Mono.error(new DataIntegrityViolationException("duplicate key"));

        // Act + Assert
        StepVerifier.create(adapter.insert(handle()))
                .expectErrorMatches(e -> e instanceof OnboardingStateException
                        && e.getMessage().equals("Concurrent duplicate commit for this credential"))
                .verify();
    }

    @Test
    void insert_otherFailure_propagatesUnchanged() {
        // Arrange
        db.rowsUpdated = Mono.error(new IllegalStateException("connection closed"));

        // Act + Assert
        StepVerifier.create(adapter.insert(handle()))
                .expectErrorMessage("connection closed")
                .verify();
    }

    private static WrappedKeyHandle handle() {
        return new WrappedKeyHandle(HOLDER_ID, CREDENTIAL_ID, new byte[48], new byte[12], new byte[16],
                "HKDF-SHA256", 1, "{\"kty\":\"EC\"}", CREATED_AT, null);
    }
}
