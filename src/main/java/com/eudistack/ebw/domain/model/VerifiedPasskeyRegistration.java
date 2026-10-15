package com.eudistack.ebw.domain.model;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** Credential record extracted from a verified registration response. */
public record VerifiedPasskeyRegistration(
        String credentialId,
        byte[] attestedCredentialData,
        UUID aaguid,
        long signCount,
        List<String> transports,
        boolean uvInitialized,
        boolean backupEligible,
        boolean backupState,
        String attestationFormat
) {

    @Override
    public boolean equals(Object other) {
        return other instanceof VerifiedPasskeyRegistration that
                && signCount == that.signCount
                && uvInitialized == that.uvInitialized
                && backupEligible == that.backupEligible
                && backupState == that.backupState
                && Objects.equals(credentialId, that.credentialId)
                && Arrays.equals(attestedCredentialData, that.attestedCredentialData)
                && Objects.equals(aaguid, that.aaguid)
                && Objects.equals(transports, that.transports)
                && Objects.equals(attestationFormat, that.attestationFormat);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(credentialId, aaguid, signCount, transports, uvInitialized, backupEligible,
                backupState, attestationFormat);
        return 31 * result + Arrays.hashCode(attestedCredentialData);
    }

    @Override
    public String toString() {
        return "VerifiedPasskeyRegistration[credentialId=[redacted], attestedCredentialData=[redacted], aaguid="
                + aaguid + ", signCount=" + signCount + ", transports=" + transports + ", uvInitialized="
                + uvInitialized + ", backupEligible=" + backupEligible + ", backupState=" + backupState
                + ", attestationFormat=" + attestationFormat + "]";
    }
}
