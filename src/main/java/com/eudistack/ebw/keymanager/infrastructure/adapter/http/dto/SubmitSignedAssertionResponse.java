package com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Response DTO for {@code POST /api/v1/keys/hybrid/sign/submit}.
 *
 * <p>Contains the key-binding JWT ({@code kb+jwt}) produced by the EBW after
 * verifying the client's signed assertion. The {@code kb_jwt} is a compact JWS
 * that binds the presentation to the holder's credential key.</p>
 *
 * <p>Spec: EUDISTACK-533 AC-04, architecture.md §6.2.</p>
 */
public record SubmitSignedAssertionResponse(
        @JsonProperty("kb_jwt") String kbJwt
) {}
