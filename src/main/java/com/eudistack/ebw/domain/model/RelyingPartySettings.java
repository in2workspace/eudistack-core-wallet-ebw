package com.eudistack.ebw.domain.model;

import java.util.List;
import java.util.Objects;

/**
 * WebAuthn Relying Party of a tenant: its canonical wallet domain ({@code rpId}), the name
 * shown by the passkey managers and the origins the Wallet App runs on.
 */
public record RelyingPartySettings(String rpId, String rpName, List<String> origins) {

    public RelyingPartySettings {
        Objects.requireNonNull(rpId, "rpId");
        Objects.requireNonNull(rpName, "rpName");
        origins = List.copyOf(origins);
        if (origins.isEmpty()) {
            throw new IllegalArgumentException("At least one origin is required");
        }
    }
}
