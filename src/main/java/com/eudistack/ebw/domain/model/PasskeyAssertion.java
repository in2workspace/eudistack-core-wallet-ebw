package com.eudistack.ebw.domain.model;

/**
 * Identifiers read from an authentication response before verifying it: the credential id
 * (base64url) to look the passkey up and the user handle returned by the authenticator.
 */
public record PasskeyAssertion(String credentialId, byte[] userHandle) {
}
