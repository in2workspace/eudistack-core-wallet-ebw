package com.eudistack.ebw.keymanager.domain.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Response from the hybrid (Passkey PRF) signing handshake — prepare step.
 *
 * <p>All byte-array fields ({@code prf_salt}, {@code wrapped_blob}, {@code iv}, {@code tag})
 * are base64url-encoded strings so the JSON body is human-readable and HTTP-safe.
 * The {@code correlation_id} ties this prepare round to its matching submit call — the
 * client MUST echo it back in {@link SubmitSignedAssertionRequest#correlationId()}.</p>
 *
 * <p>Spec: EUDISTACK-533 AC-03, architecture.md §6.2, FR-03 (operator never receives key material).</p>
 */
public record PrepareSignResponse(
        @JsonProperty("prf_salt") String prfSalt,
        @JsonProperty("wrapped_blob") String wrappedBlob,
        @JsonProperty("iv") String iv,
        @JsonProperty("tag") String tag,
        @JsonProperty("kdf_params") String kdfParams,
        @JsonProperty("signing_input") String signingInput,
        @JsonProperty("correlation_id") String correlationId
) {}
