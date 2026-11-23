package com.eudistack.ebw.domain.model.exception;

/**
 * No Wallet Instance with that identifier in the account (EUD-15 {@code instance_not_found}). Also when it
 * belongs to another account: the answer never tells them apart.
 */
public class WalletInstanceNotFoundException extends RuntimeException {

    public WalletInstanceNotFoundException() {
        super("Wallet instance not found", null, false, false);
    }
}
