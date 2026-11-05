package com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto;

import com.eudistack.ebw.keymanager.domain.model.PrfSalt;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Base64;
import java.util.Map;

/**
 * Salt of an attestation and how to derive its key from the PRF output. The public key is only
 * present when the attestation is already stored.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record PrfSaltResponse(
        @JsonProperty("credential_id") String credentialId,
        @JsonProperty("prf_salt") String prfSalt,
        Kdf kdf,
        @JsonProperty("public_jwk") Map<String, Object> publicJwk
) {

    public record Kdf(String algorithm, String info) {
    }

    private static final Kdf KDF = new Kdf("HKDF-SHA-256", "eudistack:passkey-prf:p256:v1");

    public static PrfSaltResponse withoutPublicKey(PrfSalt salt) {
        return new PrfSaltResponse(salt.credentialId(), encode(salt), KDF, null);
    }

    public static PrfSaltResponse withPublicKey(PrfSalt salt) {
        return new PrfSaltResponse(salt.credentialId(), encode(salt), KDF, salt.publicJwk());
    }

    private static String encode(PrfSalt salt) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(salt.value());
    }
}
