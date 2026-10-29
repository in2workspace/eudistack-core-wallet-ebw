package com.eudistack.ebw.infrastructure.controller.support;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;

import static org.assertj.core.api.Assertions.assertThat;

/** Unit tests for {@link BearerTickets}. */
class BearerTicketsTest {

    @Test
    void read_bearerHeader_returnsTheTicket() {
        // Arrange
        var request = MockServerHttpRequest.post("/api/v1/auth/sessions")
                .header("Authorization", "Bearer rt_9f2c4e1a7b").build();

        // Act & Assert
        assertThat(BearerTickets.read(request)).isEqualTo("rt_9f2c4e1a7b");
    }

    @Test
    void read_bearerWithSurroundingSpaces_returnsTheTrimmedTicket() {
        // Arrange
        var request = MockServerHttpRequest.post("/api/v1/auth/sessions")
                .header("Authorization", "Bearer   rt_9f2c4e1a7b  ").build();

        // Act & Assert
        assertThat(BearerTickets.read(request)).isEqualTo("rt_9f2c4e1a7b");
    }

    @Test
    void read_noAuthorizationHeader_returnsNull() {
        // Arrange
        var request = MockServerHttpRequest.post("/api/v1/auth/sessions").build();

        // Act & Assert
        assertThat(BearerTickets.read(request)).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"Basic dXNlcjpwYXNz", "Token abc", "abc", "Bearer", "Bearer ", "Bearer    "})
    void read_notABearerOrEmptyBearer_returnsNull(String header) {
        // Arrange
        var request = MockServerHttpRequest.post("/api/v1/auth/sessions").header("Authorization", header).build();

        // Act & Assert
        assertThat(BearerTickets.read(request)).isNull();
    }
}
