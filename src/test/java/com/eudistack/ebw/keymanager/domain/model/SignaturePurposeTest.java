package com.eudistack.ebw.keymanager.domain.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SignaturePurpose} enum.
 *
 * <p>Covers EUDISTACK-407 EC-05.</p>
 */
class SignaturePurposeTest {

    @Test
    void presentation_isAValue() {
        assertThat(SignaturePurpose.PRESENTATION).isNotNull();
    }

    @Test
    void auditProbe_isAValue() {
        assertThat(SignaturePurpose.AUDIT_PROBE).isNotNull();
    }

    @Test
    void valueOf_presentation_works() {
        assertThat(SignaturePurpose.valueOf("PRESENTATION")).isEqualTo(SignaturePurpose.PRESENTATION);
    }

    @Test
    void valueOf_auditProbe_works() {
        assertThat(SignaturePurpose.valueOf("AUDIT_PROBE")).isEqualTo(SignaturePurpose.AUDIT_PROBE);
    }
}
