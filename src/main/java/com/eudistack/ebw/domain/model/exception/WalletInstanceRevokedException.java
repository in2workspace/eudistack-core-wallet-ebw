package com.eudistack.ebw.domain.model.exception;

/** The Wallet Instance is revoked and never becomes active again (EUD-15 {@code instance_revoked}, FR-16). */
public class WalletInstanceRevokedException extends RuntimeException {

    public WalletInstanceRevokedException() {
        super("Wallet instance revoked", null, false, false);
    }
}
