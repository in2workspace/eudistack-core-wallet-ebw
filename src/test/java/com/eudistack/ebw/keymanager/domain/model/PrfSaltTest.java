package com.eudistack.ebw.keymanager.domain.model;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class PrfSaltTest {

    private static final Map<String, Object> JWK = Map.of("kty", "EC", "crv", "P-256", "x", "x1", "y", "y1");

    private static PrfSalt salt(byte fill, String passkeyId) {
        var value = new byte[32];
        java.util.Arrays.fill(value, fill);
        return new PrfSalt("cred-1", value, passkeyId, JWK);
    }

    @Test
    void equals_sameContentInDifferentArrays_isEqualWithTheSameHashCode() {
        // Arrange
        var first = salt((byte) 7, "passkey-1");
        var second = salt((byte) 7, "passkey-1");

        // Act
        boolean equal = first.equals(second);

        // Assert
        assertThat(equal).isTrue();
        assertThat(first).hasSameHashCodeAs(second);
    }

    @Test
    void equals_differentSaltBytes_isNotEqual() {
        // Arrange
        var first = salt((byte) 7, "passkey-1");
        var second = salt((byte) 8, "passkey-1");

        // Act
        boolean equal = first.equals(second);

        // Assert
        assertThat(equal).isFalse();
    }

    @Test
    void equals_differentPasskey_isNotEqual() {
        // Arrange
        var first = salt((byte) 7, "passkey-1");
        var second = salt((byte) 7, "passkey-2");

        // Act
        boolean equal = first.equals(second);

        // Assert
        assertThat(equal).isFalse();
    }

    @Test
    void equals_otherType_isNotEqual() {
        // Arrange
        var first = salt((byte) 7, "passkey-1");

        // Act
        boolean equal = first.equals("not a salt");

        // Assert
        assertThat(equal).isFalse();
    }

    @Test
    void toString_neverShowsTheSaltBytes() {
        // Arrange
        var salt = salt((byte) 42, "passkey-1");

        // Act
        String text = salt.toString();

        // Assert
        assertThat(text).contains("cred-1", "passkey-1", "publicKeyPresent=true").doesNotContain("42");
    }

    @Test
    void isOwnedBy_passkeyOfTheSalt_isTrueAndAnyOtherIsFalse() {
        // Arrange
        var owned = salt((byte) 1, "passkey-1");
        var orphan = new PrfSalt("cred-1", new byte[32], null, null);

        // Act + Assert
        assertThat(owned.isOwnedBy("passkey-1")).isTrue();
        assertThat(owned.isOwnedBy("passkey-2")).isFalse();
        assertThat(orphan.isOwnedBy("passkey-1")).isFalse();
    }
}
