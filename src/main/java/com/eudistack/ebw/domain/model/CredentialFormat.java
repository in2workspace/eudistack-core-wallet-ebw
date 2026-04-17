package com.eudistack.ebw.domain.model;

public enum CredentialFormat {

    JWT_VC_JSON("jwt_vc_json"),
    DC_SD_JWT("dc+sd-jwt");

    private final String value;

    CredentialFormat(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static CredentialFormat fromValue(String value) {
        for (CredentialFormat format : values()) {
            if (format.value.equals(value)) {
                return format;
            }
        }
        throw new IllegalArgumentException("Unsupported credential format: " + value);
    }
}
