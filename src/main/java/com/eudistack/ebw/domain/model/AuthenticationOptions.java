package com.eudistack.ebw.domain.model;

import java.util.List;
import java.util.UUID;

/** Data of the options to sign in with a passkey (WebAuthn {@code PublicKeyCredentialRequestOptions}). */
public record AuthenticationOptions(
        UUID ceremonyId,
        String rpId,
        byte[] challenge,
        List<UserPasskey> allowCredentials
) {
}
