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
 * <p>The client supplies the credential identifier and the full presentation payload
 * ({@code {iat, aud, nonce, sd_hash}} for a KB-JWT; the VP envelope claims for {@code jwt_vc_json})
 * already assembled by the OID4VP engine. The EBW treats {@code payload} as opaque — it does
 * NOT parse or validate its semantic content (EC-03) — and only prepends the canonical JWS
 * header for {@code format} before pinning {@code signing_input} for later verification. The
 * EBW has no visibility into the in-browser OID4VP session, so it cannot reconstruct {@code aud}
 * or {@code sd_hash} itself (design correction 2026-07-03, architecture.md §6.2).</p>
 *
 * <p>The server generates a {@code correlation_id} (UUID v4) for the session and returns it in
 * {@link PrepareSignResponse}; the client MUST echo it back in
 * {@link SubmitSignedAssertionRequest#correlationId()}.</p>
 *
 * <p>Spec: EUDISTACK-533 AC-03, EUDISTACK-536 AC-01; architecture.md §6.2.</p>
 */
public record PrepareSignRequest(
        // Allowlist (URL charset + ':') defends against log injection — credentialId flows
        // into KeyAuditCloudWatchAdapter unescaped in the log message (though JSON-serialized
        // audit payloads already escape newlines).
        @NotBlank @Size(max = 512) @Pattern(regexp = "^[A-Za-z0-9:/._-]+$") @JsonProperty("credential_id") String credentialId,
        // Coarse structural bound (claim count) on top of the global request-body size filter —
        // a real KB-JWT/VP payload has a handful of claims; anything larger is suspicious.
        @NotEmpty @Size(max = 20) @JsonProperty("payload") Map<String, Object> payload,
        @NotBlank @Size(max = 64) @JsonProperty("format") String format
) {}
