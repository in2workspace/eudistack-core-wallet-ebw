package com.eudistack.ebw.keymanager.domain.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Request to initialise the hybrid onboarding flow for a credential.
 *
 * <p>The server generates a PRF salt and returns it together with the KDF parameters so
 * the Wallet PWA can derive the wrap key client-side via
 * {@code PRF(passkey, salt) → HKDF-SHA-256(info="hybrid-wrap-v1")}.</p>
 *
 * <p>The {@code holder_id} is extracted from the DPoP-bound session token by the
 * controller — it MUST NOT be accepted from the request body (AC-06).</p>
 *
 * <p>Spec: EUDISTACK-534 AC-01, AC-06; architecture.md §6.1 step 3.</p>
 */
public record EnrollHolderInitRequest(
        @NotBlank @Size(max = 512) @JsonProperty("credential_id") String credentialId,
        @NotBlank @Size(max = 64) @JsonProperty("format") String format
) {}