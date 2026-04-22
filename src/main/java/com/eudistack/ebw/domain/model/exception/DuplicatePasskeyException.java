package com.eudistack.ebw.domain.model.exception;

public class DuplicatePasskeyException extends RuntimeException {

    public DuplicatePasskeyException() {
        super("Passkey with this credential ID already registered");
    }
}
