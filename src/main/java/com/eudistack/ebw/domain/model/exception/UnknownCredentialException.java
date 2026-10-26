package com.eudistack.ebw.domain.model.exception;

/** The tenant has no passkey with the credential id of the authentication response. */
public class UnknownCredentialException extends RuntimeException {

    public UnknownCredentialException() {
        super("Unknown passkey");
    }
}
