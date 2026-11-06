package com.eudistack.ebw.domain.model;

/** Where the private key of a bound attestation lives (EUD-11 prd §1). */
public enum CustodyMode {

    SERVER("server"),
    PASSKEY("passkey");

    private final String dbValue;

    CustodyMode(String dbValue) {
        this.dbValue = dbValue;
    }

    public String getDbValue() {
        return dbValue;
    }

    /** @return the matching constant, or {@code null} for a {@code null} column value */
    public static CustodyMode fromDbValue(String value) {
        if (value == null) {
            return null;
        }
        for (CustodyMode mode : values()) {
            if (mode.dbValue.equals(value)) {
                return mode;
            }
        }
        throw new IllegalArgumentException("Unsupported custody_mode value: " + value);
    }
}
