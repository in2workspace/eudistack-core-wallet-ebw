package com.eudistack.ebw.domain.model.exception;

/** The public key an attestation is bound to (its {@code cnf}) is not the key of its holder key (EUD-11 FR-05). */
public class HolderKeyMismatchException extends RuntimeException {

    public HolderKeyMismatchException(String message) {
        super(message);
    }
}
