package com.eudistack.ebw.domain.model;

import java.util.Arrays;
import java.util.Objects;

/**
 * Identifiers read from an authentication response before verifying it: the credential id
 * (base64url) to look the passkey up and the user handle returned by the authenticator.
 */
public record PasskeyAssertion(String credentialId, byte[] userHandle) {

    @Override
    public boolean equals(Object other) {
        return other instanceof PasskeyAssertion(var otherCredentialId, var otherUserHandle)
                && Objects.equals(credentialId, otherCredentialId)
                && Arrays.equals(userHandle, otherUserHandle);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hashCode(credentialId) + Arrays.hashCode(userHandle);
    }

    @Override
    public String toString() {
        return "PasskeyAssertion[credentialId=[redacted], userHandle=[redacted]]";
    }
}
