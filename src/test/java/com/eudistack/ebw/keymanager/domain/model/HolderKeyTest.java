package com.eudistack.ebw.keymanager.domain.model;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HolderKeyTest {

    private static final Instant NOW = Instant.parse("2026-05-26T10:00:00Z");
    private static final byte[] FAKE_KEY = new byte[]{1, 2, 3, 4, 5};
    private static final JwkPublic JWK = new JwkPublic(
            Map.of("kty", "EC", "crv", "P-256", "x", "abc", "y", "def"));

    private HolderKey validKey() {
        return new HolderKey(
                HolderKeyId.generate(),
                "tenant-1",
                "holder-1",
                "cred-1",
                CredentialFormat.SD_JWT_VC,
                KeyAlgorithm.ES256,
                FAKE_KEY.clone(),
                JWK,
                NOW,
                null);
    }

    @Test
    void constructor_allValidFields_succeeds() {
        HolderKeyId id = HolderKeyId.generate();
        var key = new HolderKey(
                id, "tenant-1", "holder-1", "cred-1",
                CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256,
                FAKE_KEY.clone(), JWK, NOW, null);

        assertThat(key.id()).isEqualTo(id);
        assertThat(key.holderId()).isEqualTo("holder-1");
        assertThat(key.credentialId()).isEqualTo("cred-1");
        assertThat(key.tenantId()).isEqualTo("tenant-1");
        assertThat(key.publicJwk()).isEqualTo(JWK);
        assertThat(key.algorithm()).isEqualTo(KeyAlgorithm.ES256);
        assertThat(key.format()).isEqualTo(CredentialFormat.SD_JWT_VC);
        assertThat(key.createdAt()).isEqualTo(NOW);
        assertThat(key.revokedAt()).isNull();
    }

    @Test
    void constructor_nullId_throwsNullPointerException() {
        assertThatThrownBy(() ->
                new HolderKey(null, "t", "h", "c",
                        CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256,
                        FAKE_KEY, JWK, NOW, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("id");
    }

    @Test
    void constructor_nullTenantId_throwsNullPointerException() {
        assertThatThrownBy(() ->
                new HolderKey(HolderKeyId.generate(), null, "h", "c",
                        CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256,
                        FAKE_KEY, JWK, NOW, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("tenantId");
    }

    @Test
    void constructor_blankTenantId_throwsIllegalArgumentException() {
        assertThatThrownBy(() ->
                new HolderKey(HolderKeyId.generate(), "  ", "h", "c",
                        CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256,
                        FAKE_KEY, JWK, NOW, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("tenantId");
    }

    @Test
    void constructor_nullHolderId_throwsNullPointerException() {
        assertThatThrownBy(() ->
                new HolderKey(HolderKeyId.generate(), "t", null, "c",
                        CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256,
                        FAKE_KEY, JWK, NOW, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("holderId");
    }

    @Test
    void constructor_nullCredentialId_throwsNullPointerException() {
        assertThatThrownBy(() ->
                new HolderKey(HolderKeyId.generate(), "t", "h", null,
                        CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256,
                        FAKE_KEY, JWK, NOW, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("credentialId");
    }

    @Test
    void constructor_nullPrivateKey_throwsNullPointerException() {
        assertThatThrownBy(() ->
                new HolderKey(HolderKeyId.generate(), "t", "h", "c",
                        CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256,
                        null, JWK, NOW, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("privateKey");
    }

    @Test
    void constructor_emptyPrivateKey_throwsIllegalArgumentException() {
        assertThatThrownBy(() ->
                new HolderKey(HolderKeyId.generate(), "t", "h", "c",
                        CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256,
                        new byte[0], JWK, NOW, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("privateKey");
    }

    @Test
    void constructor_nullPublicJwk_throwsNullPointerException() {
        assertThatThrownBy(() ->
                new HolderKey(HolderKeyId.generate(), "t", "h", "c",
                        CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256,
                        FAKE_KEY, null, NOW, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("publicJwk");
    }

    @Test
    void constructor_nullAlgorithm_throwsNullPointerException() {
        assertThatThrownBy(() ->
                new HolderKey(HolderKeyId.generate(), "t", "h", "c",
                        CredentialFormat.SD_JWT_VC, null,
                        FAKE_KEY, JWK, NOW, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("algorithm");
    }

    @Test
    void constructor_nullFormat_throwsNullPointerException() {
        assertThatThrownBy(() ->
                new HolderKey(HolderKeyId.generate(), "t", "h", "c",
                        null, KeyAlgorithm.ES256,
                        FAKE_KEY, JWK, NOW, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("format");
    }

    @Test
    void constructor_nullCreatedAt_throwsNullPointerException() {
        assertThatThrownBy(() ->
                new HolderKey(HolderKeyId.generate(), "t", "h", "c",
                        CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256,
                        FAKE_KEY, JWK, null, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("createdAt");
    }

    @Test
    void constructor_storesDefensiveCopy_mutatingOriginalArrayHasNoEffect() {
        byte[] original = new byte[]{10, 20, 30};
        var key = new HolderKey(HolderKeyId.generate(), "t", "h", "c",
                CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256,
                original, JWK, NOW, null);

        original[0] = (byte) 99;

        assertThat(key.privateKey()[0])
                .as("stored copy must not reflect mutation of the original array")
                .isEqualTo((byte) 10);
    }

    @Test
    void privateKey_accessor_returnsDefensiveCopy_mutatingReturnedArrayHasNoEffect() {
        var key = new HolderKey(HolderKeyId.generate(), "t", "h", "c",
                CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256,
                new byte[]{10, 20, 30}, JWK, NOW, null);
        byte[] returned = key.privateKey();

        returned[0] = (byte) 99;

        assertThat(key.privateKey()[0])
                .as("internal state must not change when the returned array is mutated")
                .isEqualTo((byte) 10);
    }

    @Test
    void toString_redactsPrivateKey_includesOtherFields() {
        String s = validKey().toString();

        assertThat(s)
                .as("toString must redact privateKey bytes")
                .contains("privateKey=[REDACTED]")
                .as("toString must include holderId (not redacted per spec)")
                .contains("holderId=holder-1")
                .as("toString must include tenantId")
                .contains("tenantId=tenant-1")
                .as("toString must not expose raw byte array contents")
                .doesNotContain("[B@");
    }

    @Test
    void isRevoked_returnsFalse_whenRevokedAtIsNull() {
        assertThat(validKey().isRevoked()).isFalse();
    }

    @Test
    void isRevoked_returnsTrue_whenRevokedAtIsNotNull() {
        var key = new HolderKey(HolderKeyId.generate(), "t", "h", "c",
                CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256,
                FAKE_KEY.clone(), JWK, NOW, NOW.plusSeconds(3600));
        assertThat(key.isRevoked()).isTrue();
    }

    @Test
    void holderKeyId_generate_producesUniqueValues() {
        HolderKeyId first = HolderKeyId.generate();
        HolderKeyId second = HolderKeyId.generate();
        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void holderKeyId_of_roundTrips_uuid() {
        UUID uuid = UUID.randomUUID();
        assertThat(HolderKeyId.of(uuid).value()).isEqualTo(uuid);
    }
}