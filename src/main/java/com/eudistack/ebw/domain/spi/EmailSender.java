package com.eudistack.ebw.domain.spi;

import reactor.core.publisher.Mono;

public interface EmailSender {

    Mono<Void> sendOtp(String email, String code, String from);
}
