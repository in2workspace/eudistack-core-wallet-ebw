package com.eudistack.ebw.domain.spi;

import reactor.core.publisher.Mono;

public interface HashProvider {

    Mono<String> hash(String raw);

    Mono<Boolean> verify(String raw, String hash);

    String sha256(String raw);
}
