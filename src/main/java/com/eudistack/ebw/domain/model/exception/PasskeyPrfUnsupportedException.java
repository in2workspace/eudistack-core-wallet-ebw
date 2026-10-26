package com.eudistack.ebw.domain.model.exception;

/** The tenant has passkey custody and the new passkey does not support the PRF extension. */
public class PasskeyPrfUnsupportedException extends RuntimeException {

    public PasskeyPrfUnsupportedException() {
        super("The passkey does not support the PRF extension required by the tenant");
    }
}
