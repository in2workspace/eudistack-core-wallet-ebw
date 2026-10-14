package com.eudistack.ebw.domain.model.exception;

import com.eudistack.ebw.domain.model.AuthRejectionReason;

/** The ceremony is unknown, expired or used, or the registration response does not verify. */
public class RegistrationFailedException extends RuntimeException {

    private final AuthRejectionReason reason;

    public RegistrationFailedException(AuthRejectionReason reason) {
        super(reason.code());
        this.reason = reason;
    }

    public AuthRejectionReason getReason() {
        return reason;
    }
}
