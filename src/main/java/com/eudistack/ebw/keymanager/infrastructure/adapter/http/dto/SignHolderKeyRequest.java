package com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto;

import com.eudistack.ebw.keymanager.domain.model.ConsumerOrigin;
import com.eudistack.ebw.keymanager.domain.model.SignaturePurpose;
import com.eudistack.ebw.keymanager.domain.model.SigningType;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * Request DTO for {@code POST /api/v1/keys/{keyId}/sign}.
 *
 * <p>The {@code signing_input} field is the base64url-encoded bytes to sign.
 * The EBW treats this payload as opaque — it does NOT validate the semantic structure
 * (EC-03). Validation is limited to size and presence. Max 1 MB guards against
 * payload abuse.</p>
 *
 * <p>The {@code purpose} field defaults to {@link SignaturePurpose#PRESENTATION} when absent
 * via {@code @JsonSetter(nulls = Nulls.SKIP)} combined with a record default value.
 * Note: records do not support field defaults natively — the default is applied via
 * Jackson's null-handling annotation.</p>
 *
 * <p>Spec: EUDISTACK-407 ES-01, AC-01, AC-02, AC-03.</p>
 */
public record SignHolderKeyRequest(
        @NotNull @JsonProperty("signing_type") SigningType signingType,
        @NotNull @JsonSetter(nulls = Nulls.SKIP) @JsonProperty("purpose") SignaturePurpose purpose,
        @NotBlank @Size(max = 1_048_576) @JsonProperty("signing_input") String signingInput
) {

    /**
     * Compact constructor that applies the default value for {@code purpose}.
     * Jackson will have already set it via {@code @JsonSetter}, but if the field arrives
     * as null (e.g. programmatic construction), we fall back to {@link SignaturePurpose#PRESENTATION}.
     */
    public SignHolderKeyRequest {
        if (purpose == null) {
            purpose = SignaturePurpose.PRESENTATION;
        }
    }
}
