package com.eudistack.ebw.domain.model.exception;

/** A Wallet Instance request with a missing or invalid field (EUD-15 {@code invalid_request}). */
public class InvalidWalletInstanceException extends RuntimeException {

    public InvalidWalletInstanceException(String message) {
        super(message, null, false, false);
    }
}
