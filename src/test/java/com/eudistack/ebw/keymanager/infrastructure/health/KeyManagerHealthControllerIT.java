package com.eudistack.ebw.keymanager.infrastructure.health;

import com.eudistack.ebw.keymanager.domain.port.HolderKeyCipherPort;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.mockito.Mockito.when;

/**
 * Web-layer integration test for {@link KeyManagerHealthController}.
 *
 * <p>Uses {@link WebFluxTest} to spin up the minimal WebFlux context (no DB, no crypto).
 * The {@link HolderKeyCipherPort} is replaced with a Mockito mock via {@link MockitoBean}.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-05 — GET /health/keymanager returns 200 {"status":"UP"} when cipher is operational</li>
 *   <li>AC-06 — GET /health/keymanager returns 503 {"status":"DOWN"} when cipher probe fails</li>
 * </ul>
 */
@Tag("integration")
@WebFluxTest(controllers = KeyManagerHealthController.class)
@WithMockUser
class KeyManagerHealthControllerIT {

    @MockitoBean
    HolderKeyCipherPort cipherPort;

    @Autowired
    WebTestClient webTestClient;

    @Test
    void getHealthKeymanager_returns200WithStatusUp_whenCipherIsOperational() {
        when(cipherPort.isOperational()).thenReturn(true);

        webTestClient.get().uri("/health/keymanager")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.status").isEqualTo("UP");
    }

    @Test
    void getHealthKeymanager_returns503WithStatusDown_whenCipherIsNotOperational() {
        when(cipherPort.isOperational()).thenReturn(false);

        webTestClient.get().uri("/health/keymanager")
                .exchange()
                .expectStatus().isEqualTo(503)
                .expectBody()
                .jsonPath("$.status").isEqualTo("DOWN");
    }
}