package com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Request DTO for {@code POST /api/v1/keys/hybrid/onboarding/block}.
 *
 * <p>{@code credentialId}/{@code correlationId} are validated but intentionally not threaded
 * into the {@code ONBOARDING_BLOCKED_PRF_UNSUPPORTED} audit event: it is a device-level event
 * (the holder's authenticator lacks PRF support — not tied to any one credential), and the
 * audit trail's {@code correlation_id} is always the server's own OTEL trace id (EUDISTACK-540
 * FR-16), never a client-supplied value, so the same operation can be located across logs,
 * traces, and the audit trail regardless of what the caller sends here.</p>
 */
public record BlockOnboardingRequest(
        @NotBlank @Size(max = 512) @JsonProperty("credential_id") String credentialId,
        @NotBlank @Size(max = 512) @JsonProperty("correlation_id") String correlationId
) {}
