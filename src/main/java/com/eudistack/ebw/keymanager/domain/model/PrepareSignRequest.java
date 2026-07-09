package com.eudistack.ebw.keymanager.domain.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.Map;

/**
 * Request for the hybrid (Passkey PRF) signing handshake — prepare step.
 *
 * <p>The client supplies the credential identifier and the full presentation payload, already
 * assembled by the OID4VP engine. The EBW treats {@code payload} as opaque (EC-03) and only
 * prepends the canonical JWS header for {@code format}.</p>
 *
 * <p>The server generates a {@code correlation_id} (UUID v4) for the session and returns it in
 * {@link PrepareSignResponse}; the client MUST echo it back in
 * {@link SubmitSignedAssertionRequest#correlationId()}.</p>
 *
 * <p>Spec: EUDISTACK-533 AC-03, EUDISTACK-536 AC-01; architecture.md §6.2.</p>
 */
public record PrepareSignRequest(
        @NotBlank @Size(max = 512) @Pattern(regexp = "^[A-Za-z0-9:/._-]+$") @JsonProperty("credential_id") String credentialId,
        @NotEmpty @Size(max = 20) @JsonProperty("payload") Map<String, Object> payload,
        @NotBlank @Size(max = 64) @JsonProperty("format") String format
) {}
