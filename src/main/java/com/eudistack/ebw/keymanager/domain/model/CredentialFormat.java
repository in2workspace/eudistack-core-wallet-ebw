package com.eudistack.ebw.keymanager.domain.model;

/**
 * Credential formats supported by the Key Manager bounded context.
 *
 * <p>This enum is intentionally separate from {@code com.eudistack.ebw.domain.model.CredentialFormat}
 * to avoid coupling the keymanager bounded context to the wallet storage domain, which uses
 * different format identifiers (e.g. {@code dc+sd-jwt} vs {@code SD_JWT_VC}).</p>
 *
 * <p>Spec: OID4VCI 1.0 §4 (credential format identifier), ADR-021.</p>
 */
public enum CredentialFormat {

    SD_JWT_VC("dc+sd-jwt"),
    VC_JWT("jwt_vc_json");

    private final String dbValue;

    CredentialFormat(String dbValue) {
        this.dbValue = dbValue;
    }

    /** Returns the OID4VCI format identifier used in the {@code format} column. */
    public String dbValue() {
        return dbValue;
    }

    public static CredentialFormat fromDbValue(String value) {
        for (CredentialFormat f : values()) {
            if (f.dbValue.equals(value)) return f;
        }
        throw new IllegalArgumentException("Unknown credential format: " + value);
    }
}