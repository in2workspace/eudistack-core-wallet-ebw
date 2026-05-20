package com.eudistack.ebw.wallet.profile.domain.model;

import java.time.Instant;
import java.util.Objects;

/**
 * Domain record representing the wallet discovery profile of a single tenant.
 *
 * <p>Each tenant has at most one row in {@code tenant_wallet_profile} (enforced by PK).
 * This record is the domain representation of that row — it is not an R2DBC entity.
 *
 * <p><b>Invariant (FR-10 / FR-11):</b>
 * <ul>
 *   <li>When {@code walletMode == BROWSER}, {@code keyManager} MUST be {@code null}.
 *   <li>When {@code walletMode == SERVER}, {@code keyManager} MUST be non-null.
 * </ul>
 * These rules are the primary responsibility of the PostgreSQL CHECK constraint
 * {@code chk_wallet_profile_mode_manager} and are replicated here as defense-in-depth
 * (AD-412-2): any code path that constructs this record — not only the R2DBC adapter —
 * is guaranteed to hold the invariant without reaching the database.
 *
 * @param tenant     the tenant identifier (PK of {@code tenant_wallet_profile})
 * @param walletMode the operating mode — never {@code null}
 * @param keyManager the key manager in use; {@code null} iff {@code walletMode == BROWSER}
 * @param createdAt  timestamp of first creation — never {@code null}
 * @param updatedAt  timestamp of last modification — never {@code null}
 */
public record TenantWalletProfile(
        String tenant,
        WalletMode walletMode,
        KeyManager keyManager,
        Instant createdAt,
        Instant updatedAt
) {

    /**
     * Compact constructor — validates non-null fields and the mode/key-manager invariant.
     *
     * <p>Throws {@link IllegalArgumentException} for invariant violations and
     * {@link NullPointerException} for null mandatory fields.
     */
    public TenantWalletProfile {
        Objects.requireNonNull(tenant, "tenant must not be null");
        Objects.requireNonNull(walletMode, "walletMode must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        Objects.requireNonNull(updatedAt, "updatedAt must not be null");

        if (walletMode == WalletMode.BROWSER && keyManager != null) {
            throw new IllegalArgumentException(
                    "keyManager must be null when walletMode is BROWSER (FR-10)");
        }
        if (walletMode == WalletMode.SERVER && keyManager == null) {
            throw new IllegalArgumentException(
                    "keyManager must not be null when walletMode is SERVER (FR-11)");
        }
    }
}