package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.r2dbc.postgresql.codec.Json;
import io.r2dbc.spi.R2dbcDataIntegrityViolationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PrfSaltRepository}: the mapping of the salt row, a duplicate-key race on insert is
 * reported as "not inserted" while any other integrity violation propagates. Real constraint behaviour is
 * covered by the {@code PrfSalt*IT} suites.
 */
class PrfSaltRepositoryTest {

    private static final String HOLDER_ID = UUID.randomUUID().toString();
    private static final String PASSKEY_ID = UUID.randomUUID().toString();
    private static final String CREDENTIAL_ID = "cred-1";
    private static final Map<String, Object> PUBLIC_JWK = Map.of("kty", "EC", "crv", "P-256", "x", "x1", "y", "y1");

    private DatabaseClientStub db;
    private PrfSaltRepository repository;

    @BeforeEach
    void setUp() {
        db = new DatabaseClientStub();
        repository = new PrfSaltRepository(db.client, new ObjectMapper());
    }

    @Test
    void findBy_saltWithPasskeyAndPublicKey_mapsAllOfIt() {
        // Arrange
        when(db.row.get("prf_salt", byte[].class)).thenReturn(new byte[]{9, 8, 7});
        when(db.row.get("passkey_id", UUID.class)).thenReturn(UUID.fromString(PASSKEY_ID));
        when(db.row.get("public_jwk", Json.class)).thenReturn(Json.of("{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"x1\",\"y\":\"y1\"}"));

        // Act
        var result = repository.findBy(HOLDER_ID, CREDENTIAL_ID);

        // Assert
        StepVerifier.create(result)
                .assertNext(salt -> {
                    assertThat(salt.credentialId()).isEqualTo(CREDENTIAL_ID);
                    assertThat(salt.value()).containsExactly(9, 8, 7);
                    assertThat(salt.passkeyId()).isEqualTo(PASSKEY_ID);
                    assertThat(salt.publicJwk()).isEqualTo(PUBLIC_JWK);
                })
                .verifyComplete();
        assertThat(db.bindings)
                .containsEntry("holderId", UUID.fromString(HOLDER_ID))
                .containsEntry("credentialId", CREDENTIAL_ID);
    }

    @Test
    void findBy_saltWithoutPasskeyNorPublicKey_mapsNulls() {
        // Arrange
        when(db.row.get("prf_salt", byte[].class)).thenReturn(new byte[]{1});

        // Act
        var result = repository.findBy(HOLDER_ID, CREDENTIAL_ID);

        // Assert
        StepVerifier.create(result)
                .assertNext(salt -> {
                    assertThat(salt.passkeyId()).isNull();
                    assertThat(salt.publicJwk()).isNull();
                })
                .verifyComplete();
    }

    @Test
    void findBy_noRow_completesEmpty() {
        // Arrange
        db.rowPresent = false;

        // Act
        var result = repository.findBy(HOLDER_ID, CREDENTIAL_ID);

        // Assert
        StepVerifier.create(result).verifyComplete();
    }

    @Test
    void insert_newSalt_bindsTheCompositeKeyPasskeyAndSaltAndReportsInserted() {
        // Arrange
        var salt = new byte[]{1, 2, 3};

        // Act
        var result = repository.insert(HOLDER_ID, CREDENTIAL_ID, PASSKEY_ID, salt);

        // Assert
        StepVerifier.create(result).expectNext(true).verifyComplete();
        assertThat(db.bindings)
                .containsEntry("holderId", UUID.fromString(HOLDER_ID))
                .containsEntry("credentialId", CREDENTIAL_ID)
                .containsEntry("passkeyId", UUID.fromString(PASSKEY_ID))
                .containsEntry("prfSalt", salt);
    }

    @Test
    void insert_duplicateKeyRace_reportsNotInserted() {
        // Arrange
        db.rowsUpdated = Mono.error(new DataIntegrityViolationException("duplicate",
                new R2dbcDataIntegrityViolationException("duplicate key value", "23505")));

        // Act
        var result = repository.insert(HOLDER_ID, CREDENTIAL_ID, PASSKEY_ID, new byte[]{1});

        // Assert
        StepVerifier.create(result).expectNext(false).verifyComplete();
    }

    @Test
    void insert_foreignKeyViolation_propagates() {
        // Arrange
        db.rowsUpdated = Mono.error(new DataIntegrityViolationException("fk",
                new R2dbcDataIntegrityViolationException("violates foreign key", "23503")));

        // Act
        var result = repository.insert(HOLDER_ID, CREDENTIAL_ID, PASSKEY_ID, new byte[]{1});

        // Assert
        StepVerifier.create(result).expectError(DataIntegrityViolationException.class).verify();
    }

    @Test
    void insert_integrityViolationWithoutR2dbcCause_propagates() {
        // Arrange
        db.rowsUpdated = Mono.error(new DataIntegrityViolationException("unknown"));

        // Act
        var result = repository.insert(HOLDER_ID, CREDENTIAL_ID, PASSKEY_ID, new byte[]{1});

        // Assert
        StepVerifier.create(result).expectError(DataIntegrityViolationException.class).verify();
    }

    @Test
    void insert_nonIntegrityFailure_propagates() {
        // Arrange
        db.rowsUpdated = Mono.error(new IllegalStateException("connection closed"));

        // Act
        var result = repository.insert(HOLDER_ID, CREDENTIAL_ID, PASSKEY_ID, new byte[]{1});

        // Assert
        StepVerifier.create(result).expectErrorMessage("connection closed").verify();
    }

    @Test
    void setPublicJwk_saltOfThePasskeyWithoutKey_bindsTheKeyAndReportsUpdated() {
        // Arrange
        // default stub: one row updated

        // Act
        var result = repository.setPublicJwk(HOLDER_ID, CREDENTIAL_ID, PASSKEY_ID, PUBLIC_JWK);

        // Assert
        StepVerifier.create(result).expectNext(true).verifyComplete();
        assertThat(db.bindings)
                .containsEntry("holderId", UUID.fromString(HOLDER_ID))
                .containsEntry("credentialId", CREDENTIAL_ID)
                .containsEntry("passkeyId", UUID.fromString(PASSKEY_ID))
                .containsKey("publicJwk");
        assertThat(db.executedSql.get(0)).contains("public_jwk IS NULL").contains("passkey_id = :passkeyId");
    }

    @Test
    void setPublicJwk_noMatchingRow_reportsNotUpdated() {
        // Arrange
        db.rowsUpdated = Mono.just(0L);

        // Act
        var result = repository.setPublicJwk(HOLDER_ID, CREDENTIAL_ID, PASSKEY_ID, PUBLIC_JWK);

        // Assert
        StepVerifier.create(result).expectNext(false).verifyComplete();
    }

    @Test
    void delete_existingSalt_reportsDeleted() {
        // Arrange
        // default stub: one row updated

        // Act
        var result = repository.delete(HOLDER_ID, CREDENTIAL_ID);

        // Assert
        StepVerifier.create(result).expectNext(true).verifyComplete();
        assertThat(db.bindings)
                .containsEntry("holderId", UUID.fromString(HOLDER_ID))
                .containsEntry("credentialId", CREDENTIAL_ID);
    }

    @Test
    void delete_noSalt_reportsNotDeleted() {
        // Arrange
        db.rowsUpdated = Mono.just(0L);

        // Act
        var result = repository.delete(HOLDER_ID, CREDENTIAL_ID);

        // Assert
        StepVerifier.create(result).expectNext(false).verifyComplete();
    }
}
