package com.eudistack.ebw.domain.model.exception;

public class MalformedCredentialException extends RuntimeException {

    public MalformedCredentialException(String detail) {
        super("Malformed credential: " + detail);
    }
}
