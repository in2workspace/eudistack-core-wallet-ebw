package com.eudistack.ebw.keymanager.domain.model;

import com.eudistack.ebw.domain.model.CredentialFormat;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HolderKeyTest {

    private static final Instant NOW = Instant.parse("2026-05-26T10:00:00Z");
    private static final byte[] FAKE_KEY = new byte[]{1, 2, 3, 4, 5};
    private static final String JWK = "{\"kty\":\"EC\",\"crv\":\"P-256\"}";

    private HolderKey validKey() {
        return new HolderKey("kid-1", "holder-1", "cred-1", "tenant-1",
                FAKE_KEY.clone(), JWK, "ES256", CredentialFormat.DC_SD_JWT, NOW, null);
    }

    @Test
    void constructor_allValidFields_succeeds() {
        var key = validKey();
        assertThat(key.keyId()).isEqualTo("kid-1");
        assertThat(key.holderId()).isEqualTo("holder-1");
        assertThat(key.credentialId()).isEqualTo("cred-1");
        assertThat(key.tenantId()).isEqualTo("tenant-1");
        assertThat(key.publicJwk()).isEqualTo(JWK);
        assertThat(key.algorithm()).isEqualTo("ES256");
        assertThat(key.format()).isEqualTo(CredentialFormat.DC_SD_JWT);
        assertThat(key.createdAt()).isEqualTo(NOW);
        assertThat(key.revokedAt()).isNull();
    }

    @Test
    void constructor_nullKeyId_throwsNullPointerException() {
        assertThatThrownBy(() ->
                new HolderKey(null, "h", "c", "t", FAKE_KEY, JWK, "ES256", CredentialFormat.DC_SD_JWT, NOW, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("keyId");
    }

    @Test
    void constructor_nullHolderId_throwsNullPointerException() {
        assertThatThrownBy(() ->
                new HolderKey("k", null, "c", "t", FAKE_KEY, JWK, "ES256", CredentialFormat.DC_SD_JWT, NOW, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("holderId");
    }

    @Test
    void constructor_nullCredentialId_throwsNullPointerException() {
        assertThatThrownBy(() ->
                new HolderKey("k", "h", null, "t", FAKE_KEY, JWK, "ES256", CredentialFormat.DC_SD_JWT, NOW, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("credentialId");
    }

    @Test
    void constructor_nullTenantId_throwsNullPointerException() {
        assertThatThrownBy(() ->
                new HolderKey("k", "h", "c", null, FAKE_KEY, JWK, "ES256", CredentialFormat.DC_SD_JWT, NOW, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("tenantId");
    }

    @Test
    void constructor_nullEncryptedPrivateKey_throwsNullPointerException() {
        assertThatThrownBy(() ->
                new HolderKey("k", "h", "c", "t", null, JWK, "ES256", CredentialFormat.DC_SD_JWT, NOW, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("privateKey");
    }

    @Test
    void constructor_emptyEncryptedPrivateKey_throwsIllegalArgumentException() {
        assertThatThrownBy(() ->
                new HolderKey("k", "h", "c", "t", new byte[0], JWK, "ES256", CredentialFormat.DC_SD_JWT, NOW, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("privateKey");
    }

    @Test
    void constructor_nullPublicJwk_throwsNullPointerException() {
        assertThatThrownBy(() ->
                new HolderKey("k", "h", "c", "t", FAKE_KEY, null, "ES256", CredentialFormat.DC_SD_JWT, NOW, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("publicJwk");
    }

    @Test
    void constructor_nullAlgorithm_throwsNullPointerException() {
        assertThatThrownBy(() ->
                new HolderKey("k", "h", "c", "t", FAKE_KEY, JWK, null, CredentialFormat.DC_SD_JWT, NOW, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("algorithm");
    }

    @Test
    void constructor_nullFormat_throwsNullPointerException() {
        assertThatThrownBy(() ->
                new HolderKey("k", "h", "c", "t", FAKE_KEY, JWK, "ES256", null, NOW, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("format");
    }

    @Test
    void constructor_nullCreatedAt_throwsNullPointerException() {
        assertThatThrownBy(() ->
                new HolderKey("k", "h", "c", "t", FAKE_KEY, JWK, "ES256", CredentialFormat.DC_SD_JWT, null, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("createdAt");
    }

    @Test
    void constructor_storesDefensiveCopy_mutatingOriginalArrayHasNoEffect() {
        byte[] original = new byte[]{10, 20, 30};
        var key = new HolderKey("k", "h", "c", "t", original, JWK, "ES256", CredentialFormat.DC_SD_JWT, NOW, null);

        original[0] = (byte) 99;

        assertThat(key.privateKey()[0])
                .as("stored copy must not reflect mutation of the original array")
                .isEqualTo((byte) 10);
    }

    @Test
    void privateKey_accessor_returnsDefensiveCopy_mutatingReturnedArrayHasNoEffect() {
        var key = new HolderKey("k", "h", "c", "t", new byte[]{10, 20, 30}, JWK, "ES256", CredentialFormat.DC_SD_JWT, NOW, null);
        byte[] returned = key.privateKey();

        returned[0] = (byte) 99;

        assertThat(key.privateKey()[0])
                .as("internal state must not change when the returned array is mutated")
                .isEqualTo((byte) 10);
    }

    @Test
    void toString_redactsHolderIdAndEncryptedPrivateKey() {
        String s = validKey().toString();

        assertThat(s)
                .as("toString must not expose holderId")
                .contains("holderId=[REDACTED]")
                .as("toString must not expose privateKey")
                .contains("privateKey=[REDACTED]")
                .as("toString must not expose the literal holder-1 value")
                .doesNotContain("holder-1");
    }

    @Test
    void isRevoked_returnsFalse_whenRevokedAtIsNull() {
        assertThat(validKey().isRevoked()).isFalse();
    }

    @Test
    void isRevoked_returnsTrue_whenRevokedAtIsNotNull() {
        var key = new HolderKey("k", "h", "c", "t", FAKE_KEY.clone(), JWK, "ES256",
                CredentialFormat.DC_SD_JWT, NOW, NOW.plusSeconds(3600));
        assertThat(key.isRevoked()).isTrue();
    }
}