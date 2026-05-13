package com.eudistack.ebw.wallet.config.domain.model;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Defines the operating mode of a wallet tenant.
 *
 * <p>BROWSER tenants run entirely in the browser (no server-side key management).
 * SERVER tenants rely on server-side key management.
 *
 * <p>Serializes to lowercase JSON strings per the discovery plane contract.
 */
public enum WalletMode {

    BROWSER("browser"),
    SERVER("server");

    private final String value;

    WalletMode(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    public static WalletMode fromValue(String value) {
        for (WalletMode mode : values()) {
            if (mode.value.equals(value)) {
                return mode;
            }
        }
        throw new IllegalArgumentException("Unsupported wallet_mode: " + value);
    }
}
