package com.eudistack.ebw.domain.model.exception;

public class InvalidTokenException extends RuntimeException {

    public InvalidTokenException() {
        super("Invalid or expired token");
    }

    public InvalidTokenException(String message) {
        super(message);
    }
}
