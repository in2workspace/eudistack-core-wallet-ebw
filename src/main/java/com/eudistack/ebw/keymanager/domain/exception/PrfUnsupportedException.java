package com.eudistack.ebw.keymanager.domain.exception;

public class PrfUnsupportedException extends RuntimeException {
    public PrfUnsupportedException() {
        super("Authenticator does not support PRF");
    }
}
