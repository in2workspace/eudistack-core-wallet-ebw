package com.eudistack.ebw.keymanager.domain.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Request for the hybrid (Passkey PRF) signing handshake — submit step.
 *
 * <p>The client echoes the {@code correlation_id} received from {@link PrepareSignResponse}
 * along with the PRF-derived signature produced client-side. The EBW verifies structural
 * validity only in US-01; cryptographic verification (signature vs {@code cnf.jwk})
 * is implemented in US-04.</p>
 *
 * <p>Spec: EUDISTACK-533 AC-04, ES-03, architecture.md §6.2.</p>
 */
public record SubmitSignedAssertionRequest(
        @NotBlank @Size(max = 512) @JsonProperty("credential_id") String credentialId,
        @NotBlank @JsonProperty("signature") String signature,
        @NotBlank @Size(max = 64) @JsonProperty("correlation_id") String correlationId
) {}
