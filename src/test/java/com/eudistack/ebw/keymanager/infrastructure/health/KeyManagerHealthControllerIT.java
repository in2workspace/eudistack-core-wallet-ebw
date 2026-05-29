package com.eudistack.ebw.keymanager.infrastructure.health;

import io.r2dbc.spi.Connection;
import io.r2dbc.spi.ConnectionFactory;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Web-layer integration test for {@link KeyManagerHealthController}.
 *
 * <p>Uses {@link WebFluxTest} to spin up the minimal WebFlux context (no DB).
 * The {@link ConnectionFactory} is replaced with a Mockito mock via {@link MockitoBean}.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>GET /health/keymanager returns 200 {"status":"UP"} when DB is connectable</li>
 *   <li>GET /health/keymanager returns 503 {"status":"DOWN"} when DB is not connectable</li>
 * </ul>
 */
@Tag("integration")
@WebFluxTest(controllers = KeyManagerHealthController.class)
@WithMockUser
class KeyManagerHealthControllerIT {

    @MockitoBean
    ConnectionFactory connectionFactory;

    @Autowired
    WebTestClient webTestClient;

    @Test
    void getHealthKeymanager_returns200WithStatusUp_whenDbConnectable() {
        Connection connection = mock(Connection.class);
        // Publisher<? extends Connection> return type requires doAnswer to avoid Mockito generic bounds issue
        doAnswer(inv -> Mono.just(connection)).when(connectionFactory).create();
        when(connection.close()).thenReturn(Mono.empty());

        webTestClient.get().uri("/health/keymanager")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.status").isEqualTo("UP");
    }

    @Test
    void getHealthKeymanager_returns503WithStatusDown_whenDbNotConnectable() {
        doAnswer(inv -> Mono.error(new RuntimeException("connection refused"))).when(connectionFactory).create();

        webTestClient.get().uri("/health/keymanager")
                .exchange()
                .expectStatus().isEqualTo(503)
                .expectBody()
                .jsonPath("$.status").isEqualTo("DOWN");
    }
}