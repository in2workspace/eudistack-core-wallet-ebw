package com.eudistack.ebw.support;

import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Test-only software authenticator: a discoverable ES256 passkey that answers the WebAuthn
 * options returned by the service with {@code RegistrationResponseJSON} and
 * {@code AuthenticationResponseJSON} (attestation {@code none}), like a browser would.
 *
 * <p>Its behaviour can be bent to exercise the verification failures: user verification,
 * backup flags, signature counter, origin and user handle.
 */
public class SoftwareAuthenticator {

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();
    private static final ObjectConverter OBJECT_CONVERTER = new ObjectConverter();
    private static final SecureRandom RANDOM = new SecureRandom();

    private final KeyPair keyPair;
    private final byte[] credentialId;
    private byte[] userHandle;
    private String origin;
    private long signCount;
    private long signCountStep = 1;
    private boolean userVerified = true;
    private boolean backupEligible = true;
    private boolean backupState = true;
    private boolean prfEnabled = true;

    public SoftwareAuthenticator(String origin) {
        this.origin = origin;
        this.credentialId = new byte[32];
        RANDOM.nextBytes(credentialId);
        try {
            var generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            this.keyPair = generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // ------------------------------------------------------------------ behaviour

    public SoftwareAuthenticator withOrigin(String origin) { this.origin = origin; return this; }
    public SoftwareAuthenticator withSignCount(long signCount) { this.signCount = signCount; return this; }
    /** Step added before each assertion. 0 = passkey without counter. */
    public SoftwareAuthenticator withSignCountStep(long step) { this.signCountStep = step; return this; }
    public SoftwareAuthenticator withUserVerified(boolean uv) { this.userVerified = uv; return this; }
    public SoftwareAuthenticator withBackupEligible(boolean be) { this.backupEligible = be; return this; }
    public SoftwareAuthenticator withBackupState(boolean bs) { this.backupState = bs; return this; }
    public SoftwareAuthenticator withPrfEnabled(boolean prf) { this.prfEnabled = prf; return this; }
    public SoftwareAuthenticator withUserHandle(byte[] userHandle) { this.userHandle = userHandle; return this; }

    public String credentialIdBase64Url() { return B64.encodeToString(credentialId); }
    public long signCount() { return signCount; }

    // ------------------------------------------------------------------ ceremonies

    /** Answers {@code PublicKeyCredentialCreationOptionsJSON} like {@code navigator.credentials.create}. */
    @SuppressWarnings("unchecked")
    public Map<String, Object> register(Map<String, Object> publicKey) {
        var rp = (Map<String, Object>) publicKey.get("rp");
        var user = (Map<String, Object>) publicKey.get("user");
        this.userHandle = B64D.decode((String) user.get("id"));
        var clientDataJson = clientData("webauthn.create", (String) publicKey.get("challenge"));

        var attested = new AttestedCredentialData(AAGUID.ZERO, credentialId,
                EC2COSEKey.create((ECPublicKey) keyPair.getPublic(), COSEAlgorithmIdentifier.ES256));
        var authenticatorData = new AuthenticatorData<RegistrationExtensionAuthenticatorOutput>(
                sha256((String) rp.get("id")), flags(true), signCount, attested);
        var attestationObject = new AttestationObjectConverter(OBJECT_CONVERTER)
                .convertToBytes(new AttestationObject(authenticatorData, new NoneAttestationStatement()));

        var response = new LinkedHashMap<String, Object>();
        response.put("clientDataJSON", B64.encodeToString(clientDataJson));
        response.put("attestationObject", B64.encodeToString(attestationObject));
        response.put("transports", List.of("internal", "hybrid"));

        var credential = new LinkedHashMap<String, Object>();
        credential.put("id", credentialIdBase64Url());
        credential.put("rawId", credentialIdBase64Url());
        credential.put("type", "public-key");
        credential.put("authenticatorAttachment", "platform");
        credential.put("response", response);
        credential.put("clientExtensionResults", prfEnabled ? Map.of("prf", Map.of("enabled", true)) : Map.of());
        return credential;
    }

    /** Answers {@code PublicKeyCredentialRequestOptionsJSON} like {@code navigator.credentials.get}. */
    public Map<String, Object> authenticate(Map<String, Object> publicKey) {
        signCount += signCountStep;
        var clientDataJson = clientData("webauthn.get", (String) publicKey.get("challenge"));
        var authenticatorData = new AuthenticatorDataConverter(OBJECT_CONVERTER).convert(
                new AuthenticatorData<>(sha256((String) publicKey.get("rpId")), flags(false), signCount));

        byte[] signature;
        try {
            var signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(keyPair.getPrivate());
            signer.update(ByteBuffer.allocate(authenticatorData.length + 32)
                    .put(authenticatorData).put(sha256(clientDataJson)).array());
            signature = signer.sign();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

        var response = new LinkedHashMap<String, Object>();
        response.put("clientDataJSON", B64.encodeToString(clientDataJson));
        response.put("authenticatorData", B64.encodeToString(authenticatorData));
        response.put("signature", B64.encodeToString(signature));
        response.put("userHandle", B64.encodeToString(userHandle));

        var credential = new LinkedHashMap<String, Object>();
        credential.put("id", credentialIdBase64Url());
        credential.put("rawId", credentialIdBase64Url());
        credential.put("type", "public-key");
        credential.put("authenticatorAttachment", "platform");
        credential.put("response", response);
        credential.put("clientExtensionResults", Map.of());
        return credential;
    }

    // ------------------------------------------------------------------ helpers

    private byte flags(boolean attestedCredentialData) {
        byte flags = AuthenticatorData.BIT_UP;
        if (userVerified) flags |= AuthenticatorData.BIT_UV;
        if (backupEligible) flags |= AuthenticatorData.BIT_BE;
        if (backupState) flags |= AuthenticatorData.BIT_BS;
        if (attestedCredentialData) flags |= AuthenticatorData.BIT_AT;
        return flags;
    }

    private byte[] clientData(String type, String challenge) {
        var json = "{\"type\":\"" + type + "\",\"challenge\":\"" + challenge + "\",\"origin\":\"" + origin
                + "\",\"crossOrigin\":false}";
        return json.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] sha256(String value) {
        return sha256(value.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
