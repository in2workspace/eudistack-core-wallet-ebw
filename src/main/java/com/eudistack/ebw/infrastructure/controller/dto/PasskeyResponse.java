package com.eudistack.ebw.infrastructure.controller.dto;

import com.eudistack.ebw.domain.model.UserPasskey;

import java.time.Instant;
import java.util.UUID;

/**
 * A passkey of the account for the Signal API: its identifiers and dates. The name and the type of a device
 * belong to its Wallet Instance (EUD-15), not to the passkey.
 */
public record PasskeyResponse(UUID id, String credentialId, Instant createdAt, Instant lastUsedAt) {

    public static PasskeyResponse from(UserPasskey passkey) {
        return new PasskeyResponse(passkey.getId(), passkey.getCredentialId(), passkey.getCreatedAt(),
                passkey.getLastUsedAt());
    }
}
