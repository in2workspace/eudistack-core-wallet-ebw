package com.eudistack.ebw.domain.spi;

import com.eudistack.ebw.domain.model.PasskeyAssertion;
import com.eudistack.ebw.domain.model.RelyingPartySettings;
import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.VerifiedPasskeyAssertion;
import com.eudistack.ebw.domain.model.VerifiedPasskeyRegistration;

/**
 * Verification of WebAuthn responses (JSON serialization of WebAuthn Level 3). Pure
 * computation, no I/O. Every failure is a
 * {@link com.eudistack.ebw.domain.model.exception.WebAuthnVerificationException} whose
 * message is the concrete reason, for the logs only.
 *
 * <p>User presence and user verification are always required.
 */
public interface WebAuthnVerifier {

    /** Verifies a {@code RegistrationResponseJSON} against the ceremony challenge. */
    VerifiedPasskeyRegistration verifyRegistration(String registrationResponseJson, byte[] challenge,
                                                   RelyingPartySettings relyingParty);

    /** Reads the credential id and user handle of an {@code AuthenticationResponseJSON}, without verifying it. */
    PasskeyAssertion readAssertion(String authenticationResponseJson);

    /**
     * Verifies an {@code AuthenticationResponseJSON} with the stored credential record:
     * signature, challenge, origin, RP ID, user presence and verification, signature counter
     * and backup eligibility.
     */
    VerifiedPasskeyAssertion verifyAuthentication(String authenticationResponseJson, byte[] challenge,
                                                  RelyingPartySettings relyingParty, UserPasskey passkey);
}
