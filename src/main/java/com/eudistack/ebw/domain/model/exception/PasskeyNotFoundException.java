package com.eudistack.ebw.domain.model.exception;

public class PasskeyNotFoundException extends RuntimeException {

    public PasskeyNotFoundException() {
        super("Passkey not found");
    }
}
