package com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.hibernate.validator.constraints.URL;

import java.util.List;

/**
 * Request DTO for {@code POST /api/v1/keys/generate}.
 *
 * <p>Fields use OID4VCI format identifiers (e.g. {@code dc+sd-jwt}, {@code jwt_vc_json})
 * and JWS algorithm names as defined by RFC 7518 / ADR-024.</p>
 *
 * <p>Spec: EUDISTACK-119 ES-01, OID4VCI 1.0 §7/§8.2, ADR-024.</p>
 */
public record GenerateHolderKeyRequest(
        @NotBlank @Size(max = 512) @JsonProperty("credential_id") String credentialId,
        @NotNull @JsonProperty("format") String format,
        @NotEmpty @JsonProperty("supported_algs") List<String> supportedAlgs,
        @NotBlank @URL @JsonProperty("issuer_identifier") String issuerIdentifier,
        @Nullable @Size(max = 256) @JsonProperty("c_nonce") String cNonce
) {}