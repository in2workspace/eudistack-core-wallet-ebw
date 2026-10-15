package com.eudistack.ebw.domain.model;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** Data of the options to sign in with a passkey (WebAuthn {@code PublicKeyCredentialRequestOptions}). */
public record AuthenticationOptions(
        UUID ceremonyId,
        String rpId,
        byte[] challenge,
        List<UserPasskey> allowCredentials
) {

    @Override
    public boolean equals(Object other) {
        return other instanceof AuthenticationOptions(var otherCeremonyId, var otherRpId, var otherChallenge,
                                                      var otherAllowCredentials)
                && Objects.equals(ceremonyId, otherCeremonyId)
                && Objects.equals(rpId, otherRpId)
                && Arrays.equals(challenge, otherChallenge)
                && Objects.equals(allowCredentials, otherAllowCredentials);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(ceremonyId, rpId, allowCredentials) + Arrays.hashCode(challenge);
    }

    @Override
    public String toString() {
        return "AuthenticationOptions[ceremonyId=" + ceremonyId + ", rpId=" + rpId
                + ", challenge=[redacted], allowCredentials="
                + (allowCredentials == null ? 0 : allowCredentials.size()) + " passkeys]";
    }
}
