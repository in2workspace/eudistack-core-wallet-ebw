package com.eudistack.ebw.domain.model.exception;

public class TooManyAttemptsException extends RuntimeException {

    public TooManyAttemptsException() {
        super("Too many verification attempts");
    }
}
