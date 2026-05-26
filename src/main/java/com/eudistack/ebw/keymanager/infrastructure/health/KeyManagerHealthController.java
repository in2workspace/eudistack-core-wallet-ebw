package com.eudistack.ebw.keymanager.infrastructure.health;

import io.r2dbc.spi.ConnectionFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;

@RestController
@RequestMapping("/health")
public class KeyManagerHealthController {

    private final ConnectionFactory connectionFactory;

    public KeyManagerHealthController(ConnectionFactory connectionFactory) {
        this.connectionFactory = connectionFactory;
    }

    @GetMapping("/keymanager")
    public Mono<ResponseEntity<Map<String, String>>> health() {
        return Mono.from(connectionFactory.create())
                .flatMap(conn -> Mono.from(conn.close()).thenReturn(true))
                .map(ok -> ResponseEntity.ok(Map.of("status", "UP")))
                .onErrorReturn(ResponseEntity.status(503).body(Map.of("status", "DOWN")));
    }
}