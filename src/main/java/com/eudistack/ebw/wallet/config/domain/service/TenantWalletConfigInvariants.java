package com.eudistack.ebw.wallet.config.domain.service;

import com.eudistack.ebw.wallet.config.domain.exception.ConfigInvariantViolationException;
import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
import com.eudistack.ebw.wallet.config.domain.model.WalletMode;

import java.util.Optional;

/**
 * Pure domain service that validates structural invariants for wallet tenant configuration.
 *
 * <p>No I/O, no framework dependencies. All methods are deterministic and side-effect free.
 *
 * <p>Invariants enforced:
 * <ul>
 *   <li>FR-20 (US-01, active): {@code BROWSER} mode requires {@code keyManager = null}.</li>
 *   <li>FR-21 (US-02, implemented but not fully tested until US-02): {@code SERVER} mode requires
 *       a non-null {@code keyManager}.</li>
 *   <li>FR-22 (US-02, implemented but not fully tested until US-02): {@code naturalPersonsOnly}
 *       is {@code true} if and only if {@code keyManager = HYBRID}.</li>
 * </ul>
 */
public class TenantWalletConfigInvariants {

    /**
     * Validates that the {@code walletMode} / {@code keyManager} combination is allowed.
     *
     * <p>FR-20: {@code BROWSER} requires {@code keyManager} to be absent.
     * <p>FR-21: {@code SERVER} requires {@code keyManager} to be present.
     *
     * <p>This check MUST be invoked before any persistence port is called. Unit tests (T-5)
     * verify that no port is touched when this method throws.
     *
     * @param walletMode  the requested wallet mode; must not be {@code null}
     * @param keyManager  the optional key manager value
     * @throws ConfigInvariantViolationException if the pairing violates any active invariant
     */
    public void validatePairing(WalletMode walletMode, Optional<KeyManager> keyManager) {
        if (walletMode == WalletMode.BROWSER && keyManager.isPresent()) {
            throw new ConfigInvariantViolationException(
                    "key_manager",
                    keyManager.get().getValue());
        }
        // FR-21: SERVER mode requires a non-null key_manager.
        // Implemented here for completeness (AD-S1); exhaustively tested in US-02.
        if (walletMode == WalletMode.SERVER && keyManager.isEmpty()) {
            throw new ConfigInvariantViolationException(
                    "key_manager",
                    "null");
        }
    }

    /**
     * Derives the {@code naturalPersonsOnly} flag from the {@code keyManager} value.
     *
     * <p>FR-22: the flag is {@code true} if and only if {@code keyManager = HYBRID}.
     * For BROWSER mode (where {@code keyManager} is absent) this always returns {@code false}.
     *
     * @param keyManager the optional key manager
     * @return {@code true} when {@code keyManager = HYBRID}, {@code false} otherwise
     */
    public boolean deriveNaturalPersonsOnly(Optional<KeyManager> keyManager) {
        return keyManager.map(km -> km == KeyManager.HYBRID).orElse(false);
    }
}
