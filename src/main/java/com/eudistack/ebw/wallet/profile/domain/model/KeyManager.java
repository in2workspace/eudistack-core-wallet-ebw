package com.eudistack.ebw.wallet.profile.domain.model;

/**
 * Key manager implementation used when {@link WalletMode#SERVER} is active.
 *
 * <p>Permitted values map 1-to-1 to the {@code key_manager} CHECK enum in
 * {@code tenant_wallet_profile} (see architecture.md §8.2 and FR-11 in srs.md).
 *
 * <p>When {@link WalletMode#BROWSER} is in effect, the {@code key_manager} column
 * is {@code NULL}; callers should use {@code null} instead of this enum in that case.
 * {@link #fromDbValue(String)} returns {@code null} when the input is {@code null},
 * making the R2DBC entity-to-record mapping straightforward.
 */
public enum KeyManager {

    DB("db"),
    HYBRID("hybrid"),
    HSM("hsm"),
    QTSP("qtsp");

    private final String dbValue;

    KeyManager(String dbValue) {
        this.dbValue = dbValue;
    }

    public String getDbValue() {
        return dbValue;
    }

    /**
     * Resolves a {@link KeyManager} from its database column value.
     *
     * <p>Returns {@code null} when {@code value} is {@code null}, allowing the
     * adapter to handle the browser-mode case without extra branching.
     *
     * @param value the raw string from {@code tenant_wallet_profile.key_manager}, or {@code null}
     * @return the matching constant, or {@code null} if {@code value} is {@code null}
     * @throws IllegalArgumentException if {@code value} is non-null but not a recognised key manager
     */
    public static KeyManager fromDbValue(String value) {
        if (value == null) {
            return null;
        }
        for (KeyManager km : values()) {
            if (km.dbValue.equals(value)) {
                return km;
            }
        }
        throw new IllegalArgumentException("Unsupported key_manager value: " + value);
    }
}