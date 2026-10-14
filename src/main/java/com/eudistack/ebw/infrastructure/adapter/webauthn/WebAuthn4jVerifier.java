package com.eudistack.ebw.infrastructure.adapter.webauthn;

import com.eudistack.ebw.domain.model.PasskeyAssertion;
import com.eudistack.ebw.domain.model.RelyingPartySettings;
import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.VerifiedPasskeyAssertion;
import com.eudistack.ebw.domain.model.VerifiedPasskeyRegistration;
import com.eudistack.ebw.domain.model.exception.WebAuthnVerificationException;
import com.eudistack.ebw.domain.spi.WebAuthnVerifier;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.verifier.exception.VerificationException;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * {@link WebAuthnVerifier} with {@code webauthn4j-core} (design AD-1), non-strict manager
 * without attestation trust verification ({@code attestation: none}, AD-2).
 *
 * <p>Always requires user presence and user verification. Accepted algorithms: ES256 (-7),
 * EdDSA (-8) and RS256 (-257), the ones offered in {@code pubKeyCredParams}.
 */
@Component
public class WebAuthn4jVerifier implements WebAuthnVerifier {

    /** COSE algorithms offered in {@code pubKeyCredParams}, in preference order. */
    public static final List<Long> SUPPORTED_ALGORITHMS = List.of(-7L, -8L, -257L);

    /** Longest credential id that fits {@code user_passkey.credential_id} (VARCHAR(1024)) in base64url. */
    private static final int MAX_CREDENTIAL_ID_BASE64URL_LENGTH = 1024;

    private static final List<PublicKeyCredentialParameters> PUB_KEY_CRED_PARAMS = List.of(
            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.EdDSA),
            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256));

    private static final Set<String> KNOWN_TRANSPORTS = Set.of("ble", "hybrid", "internal", "nfc", "smart-card", "usb");

    private final WebAuthnManager webAuthnManager;
    private final AttestedCredentialDataConverter attestedCredentialDataConverter;

    public WebAuthn4jVerifier() {
        var objectConverter = new ObjectConverter();
        this.webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);
        this.attestedCredentialDataConverter = new AttestedCredentialDataConverter(objectConverter);
    }

    @Override
    public VerifiedPasskeyRegistration verifyRegistration(String registrationResponseJson, byte[] challenge,
                                                          RelyingPartySettings relyingParty) {
        try {
            var parameters = new RegistrationParameters(serverProperty(challenge, relyingParty),
                    PUB_KEY_CRED_PARAMS, true, true);
            var data = webAuthnManager.verifyRegistrationResponseJSON(registrationResponseJson, parameters);
            var attestationObject = data.getAttestationObject();
            var authenticatorData = attestationObject.getAuthenticatorData();
            var attested = authenticatorData.getAttestedCredentialData();

            var credentialId = Base64UrlUtil.encodeToString(attested.getCredentialId());
            if (credentialId.length() > MAX_CREDENTIAL_ID_BASE64URL_LENGTH) {
                throw new WebAuthnVerificationException("credential id too long");
            }
            var aaguid = attested.getAaguid();
            return new VerifiedPasskeyRegistration(
                    credentialId,
                    attestedCredentialDataConverter.convert(attested),
                    aaguid == null || AAGUID.ZERO.equals(aaguid) ? null : aaguid.getValue(),
                    authenticatorData.getSignCount(),
                    transportsOf(data.getTransports()),
                    authenticatorData.isFlagUV(),
                    authenticatorData.isFlagBE(),
                    authenticatorData.isFlagBS(),
                    attestationObject.getFormat());
        } catch (VerificationException | DataConversionException | JacksonException | IllegalArgumentException e) {
            throw new WebAuthnVerificationException("registration: " + e.getClass().getSimpleName()
                    + " " + e.getMessage(), e);
        }
    }

    @Override
    public PasskeyAssertion readAssertion(String authenticationResponseJson) {
        try {
            var data = webAuthnManager.parseAuthenticationResponseJSON(authenticationResponseJson);
            if (data.getCredentialId() == null) {
                throw new WebAuthnVerificationException("missing credential id");
            }
            return new PasskeyAssertion(Base64UrlUtil.encodeToString(data.getCredentialId()), data.getUserHandle());
        } catch (DataConversionException | JacksonException | IllegalArgumentException e) {
            throw new WebAuthnVerificationException("authentication: " + e.getClass().getSimpleName()
                    + " " + e.getMessage(), e);
        }
    }

    @Override
    public VerifiedPasskeyAssertion verifyAuthentication(String authenticationResponseJson, byte[] challenge,
                                                         RelyingPartySettings relyingParty, UserPasskey passkey) {
        try {
            var credentialRecord = new CredentialRecordImpl(
                    new NoneAttestationStatement(),
                    passkey.isUvInitialized(),
                    passkey.isBackupEligible(),
                    passkey.isBackupState(),
                    passkey.getSignCount(),
                    attestedCredentialDataConverter.convert(passkey.getAttestedCredentialData()),
                    null,
                    null,
                    null,
                    null);
            var parameters = new AuthenticationParameters(serverProperty(challenge, relyingParty), credentialRecord,
                    null, true, true);
            var data = webAuthnManager.verifyAuthenticationResponseJSON(authenticationResponseJson, parameters);
            var authenticatorData = data.getAuthenticatorData();
            return new VerifiedPasskeyAssertion(authenticatorData.getSignCount(), authenticatorData.isFlagUV(),
                    authenticatorData.isFlagBS());
        } catch (VerificationException | DataConversionException | JacksonException | IllegalArgumentException e) {
            throw new WebAuthnVerificationException("authentication: " + e.getClass().getSimpleName()
                    + " " + e.getMessage(), e);
        }
    }

    private static ServerProperty serverProperty(byte[] challenge, RelyingPartySettings relyingParty) {
        Set<Origin> origins = relyingParty.origins().stream().map(Origin::new).collect(Collectors.toSet());
        return ServerProperty.builder()
                .origins(origins)
                .rpId(relyingParty.rpId())
                .challenge(new DefaultChallenge(challenge))
                .build();
    }

    private static List<String> transportsOf(Set<AuthenticatorTransport> transports) {
        if (transports == null) {
            return List.of();
        }
        return transports.stream()
                .map(AuthenticatorTransport::getValue)
                .filter(KNOWN_TRANSPORTS::contains)
                .sorted()
                .toList();
    }
}
