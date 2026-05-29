package com.eudistack.ebw.keymanager.domain.model;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class KeyAlgorithmTest {

    @ParameterizedTest(name = "{0} → jws={1}, curve={2}")
    @CsvSource({
        "ES256, ES256, P-256",
        "ES384, ES384, P-384",
        "EdDSA, EdDSA, Ed25519"
    })
    void getJwsAlgorithmName_and_getCurveName_matchSpec(
            String enumName, String expectedJws, String expectedCurve) {
        KeyAlgorithm alg = KeyAlgorithm.valueOf(enumName);
        assertThat(alg.getJwsAlgorithmName()).isEqualTo(expectedJws);
        assertThat(alg.getCurveName()).isEqualTo(expectedCurve);
    }

    @Test
    void enum_hasExactlyThreeValues() {
        assertThat(KeyAlgorithm.values()).hasSize(3);
    }

    @Test
    void jwsAlgorithmNames_areCaseSensitive_matchingIsExact() {
        // AlgorithmNegotiator matches case-sensitively per OID4VCI 1.0 §7.2.1
        for (KeyAlgorithm alg : KeyAlgorithm.values()) {
            assertThat(alg.getJwsAlgorithmName())
                    .as("jws name for %s must not be lowercase", alg)
                    .doesNotMatch("[a-z].*");
        }
    }
}