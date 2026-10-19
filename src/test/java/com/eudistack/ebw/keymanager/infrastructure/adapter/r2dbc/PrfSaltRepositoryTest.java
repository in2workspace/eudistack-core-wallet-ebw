package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc;

import io.r2dbc.spi.R2dbcDataIntegrityViolationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PrfSaltRepository} — get-or-create semantics (EC-03): a duplicate-key race on insert is
 * swallowed, any other integrity violation propagates. Real constraint behaviour is covered by the
 * {@code PrfSalt*IT} suites.
 */
class PrfSaltRepositoryTest {

    private static final String HOLDER_ID = UUID.randomUUID().toString();
    private static final String CREDENTIAL_ID = "cred-1";

    private DatabaseClientStub db;
    private PrfSaltRepository repository;

    @BeforeEach
    void setUp() {
        db = new DatabaseClientStub();
        repository = new PrfSaltRepository(db.client);
    }

    @Test
    void findBy_existingSalt_returnsItsBytes() {
        // Arrange
        when(db.row.get("prf_salt", byte[].class)).thenReturn(new byte[]{9, 8, 7});

        // Act + Assert
        StepVerifier.create(repository.findBy(HOLDER_ID, CREDENTIAL_ID))
                .assertNext(salt -> assertThat(salt).containsExactly(9, 8, 7))
                .verifyComplete();
        assertThat(db.bindings)
                .containsEntry("holderId", UUID.fromString(HOLDER_ID))
                .containsEntry("credentialId", CREDENTIAL_ID);
    }

    @Test
    void findBy_noRow_completesEmpty() {
        // Arrange
        db.rowPresent = false;

        // Act + Assert
        StepVerifier.create(repository.findBy(HOLDER_ID, CREDENTIAL_ID)).verifyComplete();
    }

    @Test
    void insert_newSalt_bindsTheCompositeKeyAndSalt() {
        // Arrange
        var salt = new byte[]{1, 2, 3};

        // Act + Assert
        StepVerifier.create(repository.insert(HOLDER_ID, CREDENTIAL_ID, salt)).verifyComplete();
        assertThat(db.bindings).containsEntry("prfSalt", salt);
    }

    @Test
    void insert_duplicateKeyRace_isSwallowed() {
        // Arrange
        db.rowsUpdated = Mono.error(new DataIntegrityViolationException("duplicate",
                new R2dbcDataIntegrityViolationException("duplicate key value", "23505")));

        // Act + Assert
        StepVerifier.create(repository.insert(HOLDER_ID, CREDENTIAL_ID, new byte[]{1})).verifyComplete();
    }

    @Test
    void insert_foreignKeyViolation_propagates() {
        // Arrange
        db.rowsUpdated = Mono.error(new DataIntegrityViolationException("fk",
                new R2dbcDataIntegrityViolationException("violates foreign key", "23503")));

        // Act + Assert
        StepVerifier.create(repository.insert(HOLDER_ID, CREDENTIAL_ID, new byte[]{1}))
                .expectError(DataIntegrityViolationException.class)
                .verify();
    }

    @Test
    void insert_integrityViolationWithoutR2dbcCause_propagates() {
        // Arrange
        db.rowsUpdated = Mono.error(new DataIntegrityViolationException("unknown"));

        // Act + Assert
        StepVerifier.create(repository.insert(HOLDER_ID, CREDENTIAL_ID, new byte[]{1}))
                .expectError(DataIntegrityViolationException.class)
                .verify();
    }

    @Test
    void insert_nonIntegrityFailure_propagates() {
        // Arrange
        db.rowsUpdated = Mono.error(new IllegalStateException("connection closed"));

        // Act + Assert
        StepVerifier.create(repository.insert(HOLDER_ID, CREDENTIAL_ID, new byte[]{1}))
                .expectErrorMessage("connection closed")
                .verify();
    }

    @Test
    void countByCredential_returnsTheFirstColumn() {
        // Arrange
        when(db.row.get(0, Long.class)).thenReturn(2L);

        // Act + Assert
        StepVerifier.create(repository.countByCredential(CREDENTIAL_ID)).expectNext(2L).verifyComplete();
        assertThat(db.bindings).containsEntry("credentialId", CREDENTIAL_ID);
    }
}
