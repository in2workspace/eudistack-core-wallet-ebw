package com.eudistack.ebw.domain.model;

/** Authenticator state after a verified authentication, to update the credential record. */
public record VerifiedPasskeyAssertion(long signCount, boolean userVerified, boolean backupState) {
}
