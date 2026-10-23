package com.eudistack.ebw.domain.model.exception;

/** Session missing, inactive for too long, past its maximum duration, ended or reused. */
public class InvalidSessionException extends RuntimeException {

    public InvalidSessionException() {
        super("Session missing, expired or ended");
    }
}
