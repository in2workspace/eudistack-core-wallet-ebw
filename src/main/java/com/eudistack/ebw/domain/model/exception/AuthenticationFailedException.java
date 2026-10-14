package com.eudistack.ebw.domain.model.exception;

import com.eudistack.ebw.domain.model.AuthRejectionReason;

/**
 * Any passkey authentication failure other than an unknown credential. The reason is recorded in
 * the logs and the audit trail only; the client always gets {@code authentication_failed}.
 */
public class AuthenticationFailedException extends RuntimeException {

    private final AuthRejectionReason reason;

    public AuthenticationFailedException(AuthRejectionReason reason) {
        super(reason.code());
        this.reason = reason;
    }

    public AuthRejectionReason getReason() {
        return reason;
    }
}
