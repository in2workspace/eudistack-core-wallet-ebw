package com.eudistack.ebw.keymanager.domain.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwsProofTest {

    private static final String COMPACT = "aaa.bbb.ccc";

    @Test
    void constructor_validArgs_storesValues() {
        JwsProof proof = new JwsProof(COMPACT, KeyAlgorithm.ES256);
        assertThat(proof.compactSerialization()).isEqualTo(COMPACT);
        assertThat(proof.algorithm()).isEqualTo(KeyAlgorithm.ES256);
    }

    @Test
    void constructor_nullCompactSerialization_throwsNullPointerException() {
        assertThatThrownBy(() -> new JwsProof(null, KeyAlgorithm.ES256))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("compactSerialization");
    }

    @Test
    void constructor_blankCompactSerialization_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> new JwsProof("  ", KeyAlgorithm.ES256))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("compactSerialization");
    }

    @Test
    void constructor_nullAlgorithm_throwsNullPointerException() {
        assertThatThrownBy(() -> new JwsProof(COMPACT, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("algorithm");
    }

    @Test
    void record_equality_twoProofsWithSameValues_areEqual() {
        JwsProof a = new JwsProof(COMPACT, KeyAlgorithm.EdDSA);
        JwsProof b = new JwsProof(COMPACT, KeyAlgorithm.EdDSA);
        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
    }
}