package com.eudistack.ebw.domain.model.exception;

/** "It was not me" token unknown, already used or expired (FR-32, AC-10). */
public class InvalidDisavowalTokenException extends RuntimeException {

    public InvalidDisavowalTokenException() {
        super("Unknown, used or expired \"it was not me\" token");
    }
}
