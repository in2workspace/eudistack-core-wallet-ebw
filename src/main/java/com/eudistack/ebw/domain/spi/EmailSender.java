package com.eudistack.ebw.domain.spi;

import reactor.core.publisher.Mono;

public interface EmailSender {

    Mono<Void> sendOtp(String email, String code);

    /** Tells the account holder that a passkey was added to an account that already had one. */
    Mono<Void> sendNewPasskeyNotice(String email);
}
