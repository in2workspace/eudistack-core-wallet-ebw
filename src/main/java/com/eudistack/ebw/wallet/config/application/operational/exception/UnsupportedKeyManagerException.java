package com.eudistack.ebw.wallet.config.application.operational.exception;

import com.eudistack.ebw.wallet.config.domain.model.KeyManager;

import java.util.Objects;

/**
 * Thrown by {@code OperationalConfigWriter} when the {@code key_manager} in the command
 * is not supported in this Story (AD-S1: only {@link KeyManager#DB_TDE} is accepted in US-03).
 *
 * <p>Maps to HTTP {@code 409 Conflict} at the controller layer (Task 8). The error message
 * references the successor Stories (US-05/06/07) that will register the other key managers.
 *
 * <p>No Spring annotations on this class: it is a plain domain-application exception.
 */
public class UnsupportedKeyManagerException extends RuntimeException {

    private final KeyManager offendingKeyManager;

    /**
     * @param offendingKeyManager the {@link KeyManager} value that is not yet supported;
     *                            must not be null
     */
    public UnsupportedKeyManagerException(KeyManager offendingKeyManager) {
        super("key_manager '"
                + Objects.requireNonNull(offendingKeyManager, "offendingKeyManager must not be null")
                + "' is not supported in US-03; see US-05/US-06/US-07 (EUDISTACK-416/417/418) "
                + "for HSM/QTSP/Hybrid support");
        this.offendingKeyManager = offendingKeyManager;
    }

    /**
     * Returns the {@link KeyManager} value that was rejected.
     */
    public KeyManager offendingKeyManager() {
        return offendingKeyManager;
    }
}
