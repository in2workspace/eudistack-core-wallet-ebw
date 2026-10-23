package com.eudistack.ebw.domain.model.exception;

/** Registration ticket missing, expired or already used. */
public class InvalidTicketException extends RuntimeException {

    public InvalidTicketException() {
        super("Registration ticket missing, expired or already used");
    }
}
