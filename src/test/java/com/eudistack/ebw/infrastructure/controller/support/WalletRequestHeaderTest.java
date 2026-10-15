package com.eudistack.ebw.infrastructure.controller.support;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Unit tests for {@link WalletRequestHeader}. */
class WalletRequestHeaderTest {

    @Test
    void require_headerIsOne_passes() {
        // Arrange
        var request = MockServerHttpRequest.post("/api/v1/auth/refresh").header("X-Wallet-Request", "1").build();

        // Act & Assert
        assertThatCode(() -> WalletRequestHeader.require(request)).doesNotThrowAnyException();
    }

    @Test
    void require_headerNameInAnotherCase_passes() {
        // Arrange: HTTP header names are case-insensitive
        var request = MockServerHttpRequest.post("/api/v1/auth/refresh").header("x-wallet-request", "1").build();

        // Act & Assert
        assertThatCode(() -> WalletRequestHeader.require(request)).doesNotThrowAnyException();
    }

    @Test
    void require_headerMissing_throwsMissingHeader() {
        // Arrange
        var request = MockServerHttpRequest.post("/api/v1/auth/refresh").build();

        // Act & Assert
        assertThatThrownBy(() -> WalletRequestHeader.require(request))
                .isInstanceOf(WalletRequestHeader.MissingWalletRequestHeaderException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"0", "true", "yes", "", " ", "11", "1 "})
    void require_headerWithAnyOtherValue_throwsMissingHeader(String value) {
        // Arrange
        var request = MockServerHttpRequest.post("/api/v1/auth/refresh").header("X-Wallet-Request", value).build();

        // Act & Assert
        assertThatThrownBy(() -> WalletRequestHeader.require(request))
                .isInstanceOf(WalletRequestHeader.MissingWalletRequestHeaderException.class);
    }

    @Test
    void name_isTheContractHeader() {
        assertThat(WalletRequestHeader.NAME).isEqualTo("X-Wallet-Request");
    }
}
