package com.eudistack.ebw.domain.model;

import java.util.UUID;

/**
 * State of a session as the filter checks it on every request (EUD-15 AD-2): whether it is still alive and,
 * if so, the Wallet Instance it is bound to when that instance is active ({@code null} otherwise).
 */
public record SessionState(boolean active, UUID walletInstanceId) {

    public static final SessionState ENDED = new SessionState(false, null);

    /** Alive and bound to an active Wallet Instance. */
    public boolean hasActiveInstance() {
        return active && walletInstanceId != null;
    }
}
