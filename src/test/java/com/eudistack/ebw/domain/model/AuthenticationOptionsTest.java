package com.eudistack.ebw.domain.model;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AuthenticationOptionsTest {

    private static final UUID CEREMONY = UUID.randomUUID();

    private static AuthenticationOptions options(byte... challenge) {
        return new AuthenticationOptions(CEREMONY, "wallet.example", challenge, List.of());
    }

    @Test
    void equals_sameArrayContent_equalWithSameHash() {
        var a = options((byte) 1, (byte) 2);
        var b = options((byte) 1, (byte) 2);

        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
    }

    @Test
    void equals_differentArrayContent_notEqual() {
        assertThat(options((byte) 1)).isNotEqualTo(options((byte) 2));
    }

    @Test
    void equals_differentOtherField_notEqual() {
        var other = new AuthenticationOptions(CEREMONY, "other.example", new byte[] {1}, List.of());

        assertThat(options((byte) 1)).isNotEqualTo(other).isNotEqualTo("x");
    }

    @Test
    void toString_withChallenge_doesNotExposeBytes() {
        var text = options((byte) 77, (byte) 88).toString();

        assertThat(text).contains("challenge=[redacted]", "wallet.example").doesNotContain("[77, 88]");
    }

    @Test
    void toString_nullAllowCredentials_countsZero() {
        var text = new AuthenticationOptions(CEREMONY, "rp", new byte[] {1}, null).toString();

        assertThat(text).contains("allowCredentials=0 passkeys");
    }
}
