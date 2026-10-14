package com.eudistack.ebw.domain.model.exception;

/**
 * A WebAuthn response did not verify. The message carries the concrete reason for the logs;
 * it is never returned to the client, which always gets the contract error.
 */
public class WebAuthnVerificationException extends RuntimeException {

    public WebAuthnVerificationException(String reason, Throwable cause) {
        super(reason, cause);
    }

    public WebAuthnVerificationException(String reason) {
        super(reason);
    }
}
