package com.eudistack.ebw.domain.model.exception;

public class InvalidTransitionException extends RuntimeException {

    public InvalidTransitionException(String from, String to) {
        super("Invalid status transition from " + from + " to " + to);
    }
}
