package com.eudistack.ebw.domain.model;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class PasskeyAssertionTest {

    @Test
    void equals_sameContent_equalWithSameHash() {
        var a = new PasskeyAssertion("cred", new byte[] {1, 2});
        var b = new PasskeyAssertion("cred", new byte[] {1, 2});

        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
    }

    @Test
    void equals_differentHandleOrCredential_notEqual() {
        var base = new PasskeyAssertion("cred", new byte[] {1});

        assertThat(base)
                .isNotEqualTo(new PasskeyAssertion("cred", new byte[] {2}))
                .isNotEqualTo(new PasskeyAssertion("other", new byte[] {1}))
                .isNotEqualTo("x");
    }

    @Test
    void toString_always_doesNotExposeCredentialIdNorHandle() {
        var text = new PasskeyAssertion("secretCredId", new byte[] {55, 66}).toString();

        assertThat(text).contains("[redacted]").doesNotContain("secretCredId", "[55, 66]");
    }
}
