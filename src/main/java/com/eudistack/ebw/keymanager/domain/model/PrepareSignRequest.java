package com.eudistack.ebw.keymanager.domain.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Request for the hybrid (Passkey PRF) signing handshake — prepare step.
 *
 * <p>The client supplies the credential identifier and the VP challenge that will be bound
 * to the PRF-derived key-binding JWT. The server generates a {@code correlation_id} (UUID v4)
 * for the session and returns it in {@link PrepareSignResponse}; the client MUST echo it back
 * in {@link SubmitSignedAssertionRequest#correlationId()}.</p>
 *
 * <p>Spec: EUDISTACK-533 AC-03, architecture.md §6.2.</p>
 */
public record PrepareSignRequest(
        @NotBlank @Size(max = 512) @JsonProperty("credential_id") String credentialId,
        @NotBlank @Size(max = 1024) @JsonProperty("vp_challenge") String vpChallenge,
        @NotBlank @Size(max = 64) @JsonProperty("format") String format
) {}
