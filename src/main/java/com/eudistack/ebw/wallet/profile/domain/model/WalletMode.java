package com.eudistack.ebw.wallet.profile.domain.model;

/**
 * Wallet operating mode as persisted in {@code tenant_wallet_profile.wallet_mode}.
 *
 * <p>Two mutually exclusive modes:
 * <ul>
 *   <li>{@link #BROWSER} — client-side EUDIW; key material lives in the browser (WebCrypto/PRF).
 *       {@code key_manager} MUST be {@code null} (enforced by DB CHECK + domain record constructor).
 *   <li>{@link #SERVER} — server-side EBW; key material managed by the configured {@link KeyManager}.
 *       {@code key_manager} MUST be non-null (enforced by DB CHECK + domain record constructor).
 * </ul>
 *
 * <p>See architecture.md §8.2 and FR-10/FR-11 in srs.md.
 */
public enum WalletMode {

    BROWSER("browser"),
    SERVER("server");

    private final String dbValue;

    WalletMode(String dbValue) {
        this.dbValue = dbValue;
    }

    public String getDbValue() {
        return dbValue;
    }

    /**
     * Resolves a {@link WalletMode} from its database column value.
     *
     * @param value the raw string as stored in {@code tenant_wallet_profile.wallet_mode}
     * @return the matching enum constant
     * @throws IllegalArgumentException if {@code value} is not a recognised wallet mode
     */
    public static WalletMode fromDbValue(String value) {
        for (WalletMode mode : values()) {
            if (mode.dbValue.equals(value)) {
                return mode;
            }
        }
        throw new IllegalArgumentException("Unsupported wallet_mode value: " + value);
    }
}