package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.exception.UnsupportedJwsAlgorithmException;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
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

    @Nested
    @DisplayName("Issuer accepts ES256")
    class IssuerAcceptsEs256 {

        static Stream<List<String>> listsWithEs256() {
            return Stream.of(
                    List.of("ES256"),
                    List.of("EdDSA", "ES384", "ES256"),
                    List.of("ES384", "RS256", "ES256")
            );
        }

        @ParameterizedTest
        @MethodSource("listsWithEs256")
        void negotiate_listContainsEs256_returnsEs256(List<String> supported) {
            // Arrange
            // supported comes from the parameter

            // Act
            KeyAlgorithm result = negotiator.negotiate(supported);

            // Assert
            assertThat(result).isEqualTo(KeyAlgorithm.ES256);
        }
    }

    @Nested
    @DisplayName("Issuer does not accept ES256")
    class IssuerDoesNotAcceptEs256 {

        static Stream<List<String>> listsWithoutEs256() {
            return Stream.of(
                    List.of("EdDSA"),
                    List.of("ES384"),
                    List.of("EdDSA", "ES384"),
                    List.of("es256"),
                    List.of()
            );
        }

        @ParameterizedTest
        @MethodSource("listsWithoutEs256")
        void negotiate_listWithoutEs256_throwsUnsupportedJwsAlgorithmException(List<String> supported) {
            // Arrange
            // supported comes from the parameter

            // Act + Assert
            assertThatThrownBy(() -> negotiator.negotiate(supported))
                    .isInstanceOf(UnsupportedJwsAlgorithmException.class);
        }

        @Test
        void negotiate_nullList_throwsUnsupportedJwsAlgorithmException() {
            // Arrange
            List<String> supported = null;

            // Act + Assert
            assertThatThrownBy(() -> negotiator.negotiate(supported))
                    .isInstanceOf(UnsupportedJwsAlgorithmException.class);
        }
    }
}
