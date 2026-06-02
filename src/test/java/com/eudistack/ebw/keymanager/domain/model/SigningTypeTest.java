package com.eudistack.ebw.keymanager.domain.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SigningType} enum and its {@code isCompatibleWith} helper.
 *
 * <p>Covers EUDISTACK-407 AC-01, AC-02, EC-02.</p>
 */
class SigningTypeTest {

    // --- KB_JWT compatibility ---

    @Test
    void kbJwt_isCompatibleWith_sdJwtVc_returnsTrue() {
        assertThat(SigningType.KB_JWT.isCompatibleWith(CredentialFormat.SD_JWT_VC)).isTrue();
    }

    @Test
    void kbJwt_isCompatibleWith_vcJwt_returnsFalse() {
        assertThat(SigningType.KB_JWT.isCompatibleWith(CredentialFormat.VC_JWT)).isFalse();
    }

    // --- VP_ENVELOPE compatibility ---

    @Test
    void vpEnvelope_isCompatibleWith_vcJwt_returnsTrue() {
        assertThat(SigningType.VP_ENVELOPE.isCompatibleWith(CredentialFormat.VC_JWT)).isTrue();
    }

    @Test
    void vpEnvelope_isCompatibleWith_sdJwtVc_returnsFalse() {
        assertThat(SigningType.VP_ENVELOPE.isCompatibleWith(CredentialFormat.SD_JWT_VC)).isFalse();
    }

    // --- enum completeness ---

    @Test
    void allValues_haveCompatibilityDefined_noSwitch_fallthrough() {
        // Ensures no new SigningType value is accidentally added without updating isCompatibleWith
        for (SigningType type : SigningType.values()) {
            for (CredentialFormat format : CredentialFormat.values()) {
                // should not throw — switch must be exhaustive
                type.isCompatibleWith(format);
            }
        }
    }
}
