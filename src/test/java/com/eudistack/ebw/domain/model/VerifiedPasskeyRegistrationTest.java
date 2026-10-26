package com.eudistack.ebw.domain.model;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class VerifiedPasskeyRegistrationTest {

    private static final UUID AAGUID = UUID.randomUUID();

    private static VerifiedPasskeyRegistration registration(String credentialId, byte data, long signCount) {
        return new VerifiedPasskeyRegistration(credentialId, new byte[] {data}, AAGUID, signCount,
                List.of("internal"), true, true, false, "none");
    }

    @Test
    void equals_sameContent_equalWithSameHash() {
        var a = registration("cred", (byte) 1, 0);
        var b = registration("cred", (byte) 1, 0);

        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
    }

    @Test
    void equals_differentField_notEqual() {
        var base = registration("cred", (byte) 1, 0);

        assertThat(base)
                .isNotEqualTo(registration("cred", (byte) 2, 0))
                .isNotEqualTo(registration("other", (byte) 1, 0))
                .isNotEqualTo(registration("cred", (byte) 1, 5))
                .isNotEqualTo("x");
    }

    @Test
    void toString_always_doesNotExposeCredentialIdNorAttestedData() {
        var text = registration("secretCredId", (byte) 93, 7).toString();

        assertThat(text)
                .contains("attestedCredentialData=[redacted]", "signCount=7")
                .doesNotContain("secretCredId", "[93]");
    }
}
