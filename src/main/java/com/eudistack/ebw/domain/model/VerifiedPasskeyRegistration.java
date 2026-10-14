package com.eudistack.ebw.domain.model;

import java.util.List;
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
}
