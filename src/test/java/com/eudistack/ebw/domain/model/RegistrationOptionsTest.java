package com.eudistack.ebw.domain.model;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class RegistrationOptionsTest {

    private static final UUID CEREMONY = UUID.randomUUID();
    private static final RelyingPartySettings RP =
            new RelyingPartySettings("wallet.example", "Wallet", List.of("https://wallet.example"));

    private static RegistrationOptions options(byte handle, byte challenge, boolean prf) {
        return new RegistrationOptions(CEREMONY, RP, new byte[] {handle}, "alice@example.com",
                new byte[] {challenge}, List.of(), prf);
    }

    @Test
    void equals_sameContent_equalWithSameHash() {
        var a = options((byte) 1, (byte) 2, true);
        var b = options((byte) 1, (byte) 2, true);

        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
    }

    @Test
    void equals_differentField_notEqual() {
        var base = options((byte) 1, (byte) 2, true);

        assertThat(base)
                .isNotEqualTo(options((byte) 9, (byte) 2, true))
                .isNotEqualTo(options((byte) 1, (byte) 9, true))
                .isNotEqualTo(options((byte) 1, (byte) 2, false))
                .isNotEqualTo("x");
    }

    @Test
    void toString_always_doesNotExposeHandleChallengeNorUserName() {
        var text = options((byte) 71, (byte) 82, true).toString();

        assertThat(text)
                .contains("userHandle=[redacted]", "challenge=[redacted]", "requestPrf=true")
                .doesNotContain("alice@example.com", "[71]", "[82]");
    }

    @Test
    void toString_nullExcludeCredentials_countsZero() {
        var withNull = new RegistrationOptions(CEREMONY, RP, new byte[] {1}, "u", new byte[] {2}, null, false);

        assertThat(withNull.toString()).contains("excludeCredentials=0 passkeys");
    }
}
