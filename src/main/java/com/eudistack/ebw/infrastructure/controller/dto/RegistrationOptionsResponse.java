package com.eudistack.ebw.infrastructure.controller.dto;

import com.eudistack.ebw.domain.model.RegistrationOptions;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Response of {@code POST /auth/passkeys/registration/options}: {@code PublicKeyCredentialCreationOptionsJSON}. */
public record RegistrationOptionsResponse(UUID ceremonyId, PublicKey publicKey) {

    /** Milliseconds the browser waits for the user when creating a passkey. */
    public static final long TIMEOUT_MILLIS = 120_000;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record PublicKey(
            RelyingParty rp,
            User user,
            String challenge,
            List<CredentialParameter> pubKeyCredParams,
            long timeout,
            List<CredentialDescriptorJson> excludeCredentials,
            AuthenticatorSelection authenticatorSelection,
            String attestation,
            Map<String, Object> extensions
    ) {}

    public record RelyingParty(String id, String name) {}

    public record User(String id, String name, String displayName) {}

    public record CredentialParameter(String type, long alg) {}

    public record AuthenticatorSelection(String residentKey, String userVerification) {}

    public static RegistrationOptionsResponse from(RegistrationOptions options, List<Long> algorithms) {
        var b64 = Base64.getUrlEncoder().withoutPadding();
        var publicKey = new PublicKey(
                new RelyingParty(options.relyingParty().rpId(), options.relyingParty().rpName()),
                new User(b64.encodeToString(options.userHandle()), options.userName(), options.userName()),
                b64.encodeToString(options.challenge()),
                algorithms.stream().map(alg -> new CredentialParameter("public-key", alg)).toList(),
                TIMEOUT_MILLIS,
                options.excludeCredentials().stream().map(CredentialDescriptorJson::from).toList(),
                new AuthenticatorSelection("required", "required"),
                "none",
                options.requestPrf() ? Map.of("prf", Map.of()) : null);
        return new RegistrationOptionsResponse(options.ceremonyId(), publicKey);
    }
}
