package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link PrfSaltRow}.
 *
 * <p>Verifies that the R2DBC POJO preserves the raw byte array without any
 * base64/hex transformation (EC-04, EUDISTACK-537 AC-01), and that all fields
 * round-trip correctly through getters and setters.</p>
 *
 * <p>Spec: EUDISTACK-537 T8; AC-01, EC-04.</p>
 */
class PrfSaltRowTest {

    private static final int SALT_BYTES = 32;

    // ------------------------------------------------------------------ AC-01, EC-04

    @Test
    void prfSalt_32RandomBytes_preservedExactlyWithoutTransformation() {
        byte[] rawSalt = new byte[SALT_BYTES];
        new SecureRandom().nextBytes(rawSalt);
        byte[] snapshot = rawSalt.clone();

        PrfSaltRow row = new PrfSaltRow();
        row.setPrfSalt(rawSalt);

        assertThat(row.getPrfSalt()).hasSize(SALT_BYTES);
        assertThat(row.getPrfSalt()).isEqualTo(snapshot);
    }

    @Test
    void prfSalt_length_isExactly32() {
        PrfSaltRow row = new PrfSaltRow();
        row.setPrfSalt(new byte[SALT_BYTES]);

        assertThat(row.getPrfSalt()).hasSize(SALT_BYTES);
    }

    @Test
    void prfSalt_distinctRandomBytes_areNotAllZero() {
        byte[] salt = new byte[SALT_BYTES];
        new SecureRandom().nextBytes(salt);

        PrfSaltRow row = new PrfSaltRow();
        row.setPrfSalt(salt);

        // CSPRNG output across 32 bytes is astronomically unlikely to be all-zero
        boolean allZero = true;
        for (byte b : row.getPrfSalt()) {
            if (b != 0) {
                allZero = false;
                break;
            }
        }
        assertThat(allZero).as("32 CSPRNG bytes should not all be zero").isFalse();
    }

    // ------------------------------------------------------------------ holderId

    @Test
    void holderId_isUuid_roundTripsCorrectly() {
        UUID holderId = UUID.randomUUID();

        PrfSaltRow row = new PrfSaltRow();
        row.setHolderId(holderId);

        assertThat(row.getHolderId()).isInstanceOf(UUID.class);
        assertThat(row.getHolderId()).isEqualTo(holderId);
    }

    @Test
    void holderId_version4_isOpaque() {
        UUID holderId = UUID.randomUUID();

        PrfSaltRow row = new PrfSaltRow();
        row.setHolderId(holderId);

        assertThat(row.getHolderId().version()).isEqualTo(4);
    }

    // ------------------------------------------------------------------ credentialId

    @Test
    void credentialId_isString_roundTripsCorrectly() {
        String credentialId = "cred-test-" + UUID.randomUUID();

        PrfSaltRow row = new PrfSaltRow();
        row.setCredentialId(credentialId);

        assertThat(row.getCredentialId()).isInstanceOf(String.class);
        assertThat(row.getCredentialId()).isEqualTo(credentialId);
    }

    // ------------------------------------------------------------------ createdAt

    @Test
    void createdAt_roundTripsCorrectly() {
        Instant now = Instant.now();

        PrfSaltRow row = new PrfSaltRow();
        row.setCreatedAt(now);

        assertThat(row.getCreatedAt()).isEqualTo(now);
    }

    @Test
    void createdAt_isInstant() {
        PrfSaltRow row = new PrfSaltRow();
        row.setCreatedAt(Instant.now());

        assertThat(row.getCreatedAt()).isInstanceOf(Instant.class);
    }

    // ------------------------------------------------------------------ all fields

    @Test
    void allFields_setTogether_areIndependent() {
        UUID holderId = UUID.randomUUID();
        String credentialId = "cred-all-fields";
        byte[] salt = new byte[SALT_BYTES];
        new SecureRandom().nextBytes(salt);
        Instant createdAt = Instant.parse("2025-01-15T10:00:00Z");

        PrfSaltRow row = new PrfSaltRow();
        row.setHolderId(holderId);
        row.setCredentialId(credentialId);
        row.setPrfSalt(salt);
        row.setCreatedAt(createdAt);

        assertThat(row.getHolderId()).isEqualTo(holderId);
        assertThat(row.getCredentialId()).isEqualTo(credentialId);
        assertThat(row.getPrfSalt()).isEqualTo(salt);
        assertThat(row.getCreatedAt()).isEqualTo(createdAt);
    }
}
