package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.exception.UnsupportedJwsAlgorithmException;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AlgorithmNegotiatorTest {

    private AlgorithmNegotiator negotiator;

    @BeforeEach
    void setUp() {
        negotiator = new AlgorithmNegotiator();
    }

    // --- preference order (ADR-024: EdDSA > ES384 > ES256) ---

    @Test
    void negotiate_issuerSupportsAll_selectsEdDSA() {
        KeyAlgorithm result = negotiator.negotiate(List.of("EdDSA", "ES384", "ES256"));
        assertThat(result).isEqualTo(KeyAlgorithm.EdDSA);
    }

    @Test
    void negotiate_issuerSupportsES384AndES256_selectsES384() {
        KeyAlgorithm result = negotiator.negotiate(List.of("ES384", "ES256"));
        assertThat(result).isEqualTo(KeyAlgorithm.ES384);
    }

    @Test
    void negotiate_issuerSupportsOnlyES256_selectsES256() {
        KeyAlgorithm result = negotiator.negotiate(List.of("ES256"));
        assertThat(result).isEqualTo(KeyAlgorithm.ES256);
    }

    @Test
    void negotiate_issuerSupportsOnlyEdDSA_selectsEdDSA() {
        KeyAlgorithm result = negotiator.negotiate(List.of("EdDSA"));
        assertThat(result).isEqualTo(KeyAlgorithm.EdDSA);
    }

    @Test
    void negotiate_issuerListContainsAdditionalUnknownAlgs_selectsFirstMatchByPreference() {
        KeyAlgorithm result = negotiator.negotiate(List.of("RS256", "PS256", "ES256"));
        assertThat(result).isEqualTo(KeyAlgorithm.ES256);
    }

    // --- error paths ---

    @Test
    void negotiate_nullList_throwsUnsupportedJwsAlgorithmException() {
        assertThatThrownBy(() -> negotiator.negotiate(null))
                .isInstanceOf(UnsupportedJwsAlgorithmException.class);
    }

    @Test
    void negotiate_emptyList_throwsUnsupportedJwsAlgorithmException() {
        assertThatThrownBy(() -> negotiator.negotiate(List.of()))
                .isInstanceOf(UnsupportedJwsAlgorithmException.class);
    }

    @Test
    void negotiate_noIntersection_throwsUnsupportedJwsAlgorithmException() {
        assertThatThrownBy(() -> negotiator.negotiate(List.of("RS256", "PS256")))
                .isInstanceOf(UnsupportedJwsAlgorithmException.class);
    }

    // --- case sensitivity (OID4VCI 1.0 §7.2.1) ---

    @Test
    void negotiate_wrongCase_edDSA_lowercase_noMatch_throws() {
        assertThatThrownBy(() -> negotiator.negotiate(List.of("eddsa", "es256")))
                .isInstanceOf(UnsupportedJwsAlgorithmException.class);
    }

    @Test
    void negotiate_wrongCase_es256_lowercase_noMatch_throws() {
        assertThatThrownBy(() -> negotiator.negotiate(List.of("es256")))
                .isInstanceOf(UnsupportedJwsAlgorithmException.class);
    }

    static Stream<List<String>> singleAlgorithmCases() {
        return Stream.of(
                List.of("EdDSA"),
                List.of("ES384"),
                List.of("ES256")
        );
    }

    @ParameterizedTest
    @MethodSource("singleAlgorithmCases")
    void negotiate_singleSupportedAlgorithm_returnsIt(List<String> supported) {
        KeyAlgorithm result = negotiator.negotiate(supported);
        assertThat(result.getJwsAlgorithmName()).isEqualTo(supported.get(0));
    }
}