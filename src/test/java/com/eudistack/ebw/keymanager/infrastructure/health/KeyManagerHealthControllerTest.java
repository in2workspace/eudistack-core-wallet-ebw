package com.eudistack.ebw.keymanager.infrastructure.health;

import com.eudistack.ebw.keymanager.domain.port.HolderKeyCipherPort;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class KeyManagerHealthControllerTest {

    private final HolderKeyCipherPort cipherPort = mock(HolderKeyCipherPort.class);
    private final KeyManagerHealthController controller = new KeyManagerHealthController(cipherPort);

    @Test
    void health_returnsOkWithStatusUp_whenCipherIsOperational() {
        when(cipherPort.isOperational()).thenReturn(true);

        StepVerifier.create(controller.health())
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                    assertThat(response.getBody()).containsEntry("status", "UP");
                })
                .verifyComplete();
    }

    @Test
    void health_returnsServiceUnavailableWithStatusDown_whenCipherIsNotOperational() {
        when(cipherPort.isOperational()).thenReturn(false);

        StepVerifier.create(controller.health())
                .assertNext(response -> {
                    assertThat(response.getStatusCode().value()).isEqualTo(503);
                    assertThat(response.getBody()).containsEntry("status", "DOWN");
                })
                .verifyComplete();
    }
}