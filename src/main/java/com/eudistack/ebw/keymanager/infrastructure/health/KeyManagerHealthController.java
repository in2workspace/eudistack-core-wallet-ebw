package com.eudistack.ebw.keymanager.infrastructure.health;

import com.eudistack.ebw.keymanager.domain.port.HolderKeyCipherPort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;

@RestController
@RequestMapping("/health")
public class KeyManagerHealthController {

    private final HolderKeyCipherPort cipherPort;

    public KeyManagerHealthController(HolderKeyCipherPort cipherPort) {
        this.cipherPort = cipherPort;
    }

    @GetMapping("/keymanager")
    public Mono<ResponseEntity<Map<String, String>>> health() {
        return Mono.fromCallable(cipherPort::isOperational)
                .map(operational -> operational
                        ? ResponseEntity.ok(Map.of("status", "UP"))
                        : ResponseEntity.status(503).body(Map.of("status", "DOWN")));
    }
}