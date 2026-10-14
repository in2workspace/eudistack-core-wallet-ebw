package com.eudistack.ebw.domain.model.exception;

/**
 * Any passkey authentication failure other than an unknown credential. The message is the
 * concrete reason, for the logs and the audit trail only.
 */
public class AuthenticationFailedException extends RuntimeException {

    public AuthenticationFailedException(String reason) {
        super(reason);
    }
}
