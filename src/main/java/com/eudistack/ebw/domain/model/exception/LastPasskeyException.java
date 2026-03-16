package com.eudistack.ebw.domain.model.exception;

public class LastPasskeyException extends RuntimeException {

    public LastPasskeyException() {
        super("Cannot delete the last passkey");
    }
}
