package com.eudistack.ebw.keymanager.infrastructure.health;

import io.r2dbc.spi.Connection;
import io.r2dbc.spi.ConnectionFactory;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class KeyManagerHealthControllerTest {

    private final ConnectionFactory connectionFactory = mock(ConnectionFactory.class);
    private final Connection connection = mock(Connection.class);
    private final KeyManagerHealthController controller = new KeyManagerHealthController(connectionFactory);

    @Test
    void health_returnsOkWithStatusUp_whenDbConnectable() {
        // Publisher<? extends Connection> return type requires explicit cast to compile with Mockito
        doAnswer(inv -> Mono.just(connection)).when(connectionFactory).create();
        when(connection.close()).thenReturn(Mono.empty());

        StepVerifier.create(controller.health())
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                    assertThat(response.getBody()).containsEntry("status", "UP");
                })
                .verifyComplete();
    }

    @Test
    void health_returnsServiceUnavailableWithStatusDown_whenDbNotConnectable() {
        doAnswer(inv -> Mono.error(new RuntimeException("connection refused"))).when(connectionFactory).create();

        StepVerifier.create(controller.health())
                .assertNext(response -> {
                    assertThat(response.getStatusCode().value()).isEqualTo(503);
                    assertThat(response.getBody()).containsEntry("status", "DOWN");
                })
                .verifyComplete();
    }
}
