package com.eudistack.ebw.infrastructure.adapter.crypto;

import com.eudistack.ebw.domain.spi.HashProvider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

@Component
public class BcryptHashProvider implements HashProvider {

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(10);

    @Override
    public Mono<String> hash(String raw) {
        return Mono.fromCallable(() -> encoder.encode(raw))
                .subscribeOn(Schedulers.boundedElastic());
    }

    @Override
    public Mono<Boolean> verify(String raw, String hash) {
        return Mono.fromCallable(() -> encoder.matches(raw, hash))
                .subscribeOn(Schedulers.boundedElastic());
    }

    @Override
    public String sha256(String raw) {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            var hashBytes = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
