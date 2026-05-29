package com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto;

import com.eudistack.ebw.keymanager.domain.model.SignHolderKeyResult;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Response DTO for {@code POST /api/v1/keys/{keyId}/sign}.
 *
 * <p>All fields are public information — the JWS contains the signature but never
 * private key material (NFR-SEC-03). The {@code jkt} identifies the key used without
 * exposing it.</p>
 *
 * <p>Spec: EUDISTACK-407 AC-01, AC-02, FR-20.</p>
 */
public record SignHolderKeyResponse(
        @JsonProperty("jws") String jws,
        @JsonProperty("algorithm") String algorithm,
        @JsonProperty("jkt") String jkt
) {

    public static SignHolderKeyResponse from(SignHolderKeyResult result) {
        return new SignHolderKeyResponse(
                result.jwsCompact(),
                result.algorithm().getJwsAlgorithmName(),
                result.jkt()
        );
    }
}
