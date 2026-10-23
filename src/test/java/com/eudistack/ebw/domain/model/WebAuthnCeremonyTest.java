package com.eudistack.ebw.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class WebAuthnCeremonyTest {

    private static final UUID ID = UUID.randomUUID();
    private static final UUID USER = UUID.randomUUID();
    private static final Instant INSTANT = Instant.parse("2026-01-01T00:00:00Z");

    private static WebAuthnCeremony ceremony(byte fill) {
        var challenge = new byte[WebAuthnCeremony.CHALLENGE_LENGTH];
        Arrays.fill(challenge, fill);
        return new WebAuthnCeremony(ID, CeremonyType.REGISTRATION, challenge, USER, INSTANT, null, INSTANT);
    }

    @Test
    void equals_sameContent_equalWithSameHash() {
        var a = ceremony((byte) 1);
        var b = ceremony((byte) 1);

        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
    }

    @Test
    void equals_differentChallengeOrField_notEqual() {
        var base = ceremony((byte) 1);
        var consumed = new WebAuthnCeremony(ID, CeremonyType.REGISTRATION, base.challenge(), USER, INSTANT,
                INSTANT, INSTANT);

        assertThat(base).isNotEqualTo(ceremony((byte) 2)).isNotEqualTo(consumed).isNotEqualTo("x");
    }

    @Test
    void toString_always_doesNotExposeChallengeBytes() {
        var text = ceremony((byte) 99).toString();

        assertThat(text).contains("challenge=[redacted]", "type=REGISTRATION").doesNotContain("99, 99");
    }

    @Test
    void start_wrongChallengeLength_throws() {
        var shortChallenge = new byte[3];

        assertThatThrownBy(() -> WebAuthnCeremony.start(CeremonyType.REGISTRATION, shortChallenge, USER))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
