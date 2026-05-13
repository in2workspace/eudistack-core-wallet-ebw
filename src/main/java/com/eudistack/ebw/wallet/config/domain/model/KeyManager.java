package com.eudistack.ebw.wallet.config.domain.model;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Identifies the key management backend used by a SERVER-mode tenant.
 *
 * <p>Absent for BROWSER-mode tenants (invariant FR-20: BROWSER requires key_manager = null).
 *
 * <p>Serializes to kebab-case JSON strings per the discovery plane contract.
 */
public enum KeyManager {

    DB_TDE("db-tde"),
    HYBRID("hybrid"),
    HSM("hsm"),
    QTSP("qtsp");

    private final String value;

    KeyManager(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    public static KeyManager fromValue(String value) {
        for (KeyManager km : values()) {
            if (km.value.equals(value)) {
                return km;
            }
        }
        throw new IllegalArgumentException("Unsupported key_manager: " + value);
    }
}
