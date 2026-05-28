package com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto;

import com.eudistack.ebw.keymanager.domain.model.HolderKeyResult;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.annotation.Nullable;

import java.util.Map;

/**
 * Response DTO for {@code POST /api/v1/keys/generate}.
 *
 * <p>{@code warning} is present (value {@code "existing_key_algorithm_used"}) when the
 * key was fetched from an earlier issuance rather than freshly generated (EC-01 / ES-03 — ADR-021).
 * Consumers MUST handle this signal to distinguish "new key" from "existing key reused".</p>
 *
 * <p>Spec: EUDISTACK-119 AC-01, EC-01, ES-03, ADR-021.</p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record GenerateHolderKeyResponse(
        @JsonProperty("key_id") String keyId,
        @JsonProperty("public_jwk") Map<String, Object> publicJwk,
        @JsonProperty("jws_proof") String jwsProof,
        @Nullable @JsonProperty("warning") String warning
) {

    private static final String WARN_EXISTING_KEY = "existing_key_algorithm_used";

    public static GenerateHolderKeyResponse from(HolderKeyResult result) {
        return new GenerateHolderKeyResponse(
                result.keyId().value().toString(),
                result.publicJwk().claims(),
                result.jwsProof().compactSerialization(),
                result.created() ? null : WARN_EXISTING_KEY
        );
    }
}