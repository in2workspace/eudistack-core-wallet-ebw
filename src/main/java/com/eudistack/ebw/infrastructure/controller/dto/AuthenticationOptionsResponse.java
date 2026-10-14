package com.eudistack.ebw.infrastructure.controller.dto;

import com.eudistack.ebw.domain.model.AuthenticationOptions;

import java.util.Base64;
import java.util.List;
import java.util.UUID;

/** Response of {@code POST /auth/sessions/options}: {@code PublicKeyCredentialRequestOptionsJSON}. */
public record AuthenticationOptionsResponse(UUID ceremonyId, PublicKey publicKey) {

    /** Milliseconds the browser waits for the user when using a passkey. */
    public static final long TIMEOUT_MILLIS = 60_000;

    public record PublicKey(
            String challenge,
            long timeout,
            String rpId,
            List<CredentialDescriptorJson> allowCredentials,
            String userVerification
    ) {}

    public static AuthenticationOptionsResponse from(AuthenticationOptions options) {
        var publicKey = new PublicKey(
                Base64.getUrlEncoder().withoutPadding().encodeToString(options.challenge()),
                TIMEOUT_MILLIS,
                options.rpId(),
                options.allowCredentials().stream().map(CredentialDescriptorJson::from).toList(),
                "required");
        return new AuthenticationOptionsResponse(options.ceremonyId(), publicKey);
    }
}
