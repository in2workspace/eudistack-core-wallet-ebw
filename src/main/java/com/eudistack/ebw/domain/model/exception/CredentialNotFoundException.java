package com.eudistack.ebw.domain.model.exception;

public class CredentialNotFoundException extends RuntimeException {

    public CredentialNotFoundException() {
        super("Credential not found");
    }
}
