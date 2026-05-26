package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.model.JwkPublic;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.model.PlaintextHandle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Generates and reconstructs holder key pairs for OID4VCI proof-of-possession.
 *
 * <p>Supported algorithms (per ADR-024): EdDSA (Ed25519), ES384 (P-384), ES256 (P-256).
 * All cryptographic operations delegate to BouncyCastle registered as a JCA provider.</p>
 *
 * <p>Key hygiene: private key bytes are wrapped in a {@link PlaintextHandle} whose zeroizer
 * fills the raw byte array with zeros. The caller MUST close the handle after use.</p>
 *
 * <p>This class is a plain bean — instantiated in {@code KeyManagerConfiguration} without
 * Spring annotations to keep it framework-free.</p>
 *
 * <p>Spec: EUDISTACK-119, ADR-024, ADR-099, RFC 7518 §6 (EC/OKP key types).</p>
 */
public class HolderKeyFactory {

    /**
     * PKCS#8 DER prefix for an Ed25519 private key seed (32 bytes).
     *
     * <p>Encoding: SEQUENCE { INTEGER 0 (version), SEQUENCE { OID 1.3.101.112 } (Ed25519),
     * OCTET STRING { OCTET STRING { seed } } }
     * = 30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 &lt;32-byte-seed&gt;</p>
     */
    private static final byte[] ED25519_PKCS8_PREFIX = {
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
    };

    /**
     * Registers BouncyCastle as a JCA provider if it is not already registered.
     * This call is idempotent — {@link Security#addProvider} is a no-op if the provider
     * is already present.
     */
    public HolderKeyFactory() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Generates a fresh key pair for the given algorithm.
     *
     * @param algorithm the target algorithm; must not be null
     * @return a {@link GeneratedKeyPair} containing a zeroizable private key handle and
     *         the corresponding public JWK
     * @throws IllegalStateException if the JCA/BC provider is unavailable or key generation
     *                               fails unexpectedly
     */
    public GeneratedKeyPair generate(KeyAlgorithm algorithm) {
        try {
            KeyPair keyPair = generateKeyPair(algorithm);
            byte[] rawPrivateBytes = extractRawPrivateBytes(keyPair.getPrivate(), algorithm);
            PlaintextHandle<PrivateKey> handle = buildHandle(keyPair.getPrivate(), rawPrivateBytes);
            JwkPublic publicJwk = buildPublicJwk(keyPair, algorithm);
            return new GeneratedKeyPair(handle, publicJwk);
        } catch (NoSuchAlgorithmException | NoSuchProviderException
                 | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException(
                    "Key generation failed for algorithm: " + algorithm, e);
        }
    }

    /**
     * Reconstructs a {@link PrivateKey} from raw bytes and wraps it in a zeroizable handle.
     *
     * <p>For EC keys (ES256/ES384), {@code privateKeyBytes} must be the raw scalar (big-endian,
     * 32 or 48 bytes respectively). For EdDSA (Ed25519), {@code privateKeyBytes} must be the
     * 32-byte seed.</p>
     *
     * <p>The zeroizer zeros the caller-provided {@code privateKeyBytes} array on close.
     * The caller MUST NOT reuse the array after passing it here.</p>
     *
     * @param privateKeyBytes raw private key material; ownership is transferred to the handle
     * @param algorithm       the algorithm that the key belongs to
     * @return a {@link PlaintextHandle} wrapping the reconstructed {@link PrivateKey}
     * @throws IllegalStateException if reconstruction fails
     */
    public PlaintextHandle<PrivateKey> fromBytes(byte[] privateKeyBytes, KeyAlgorithm algorithm) {
        try {
            PrivateKey privateKey = reconstructPrivateKey(privateKeyBytes, algorithm);
            return new PlaintextHandle<>(privateKey, () -> Arrays.fill(privateKeyBytes, (byte) 0));
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            throw new IllegalStateException(
                    "Failed to reconstruct PrivateKey for algorithm: " + algorithm, e);
        }
    }

    // --- private helpers ---

    private KeyPair generateKeyPair(KeyAlgorithm algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException {
        switch (algorithm) {
            case ES256 -> {
                KeyPairGenerator gen =
                        KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
                gen.initialize(new ECGenParameterSpec("P-256"));
                return gen.generateKeyPair();
            }
            case ES384 -> {
                KeyPairGenerator gen =
                        KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
                gen.initialize(new ECGenParameterSpec("P-384"));
                return gen.generateKeyPair();
            }
            case EdDSA -> {
                KeyPairGenerator gen =
                        KeyPairGenerator.getInstance(
                                "Ed25519", BouncyCastleProvider.PROVIDER_NAME);
                return gen.generateKeyPair();
            }
            default -> throw new IllegalArgumentException(
                    "Unsupported algorithm: " + algorithm);
        }
    }

    /**
     * Extracts the minimal raw private key bytes for zeroization purposes.
     *
     * <p>For EC keys: the private scalar {@code s} as an unsigned big-endian byte array
     * padded to the curve's byte length. For Ed25519: the 32-byte seed extracted from
     * the PKCS#8 encoding (last 32 bytes).</p>
     */
    private byte[] extractRawPrivateBytes(PrivateKey privateKey, KeyAlgorithm algorithm) {
        switch (algorithm) {
            case ES256 -> {
                ECPrivateKey ecKey = (ECPrivateKey) privateKey;
                return toUnsignedBytes(ecKey.getS(), 32);
            }
            case ES384 -> {
                ECPrivateKey ecKey = (ECPrivateKey) privateKey;
                return toUnsignedBytes(ecKey.getS(), 48);
            }
            case EdDSA -> {
                // PKCS#8 encoding: prefix (16 bytes) + 32-byte seed
                byte[] pkcs8 = privateKey.getEncoded();
                return Arrays.copyOfRange(pkcs8, pkcs8.length - 32, pkcs8.length);
            }
            default -> throw new IllegalArgumentException(
                    "Unsupported algorithm: " + algorithm);
        }
    }

    private PlaintextHandle<PrivateKey> buildHandle(PrivateKey privateKey, byte[] rawBytes) {
        return new PlaintextHandle<>(privateKey, () -> Arrays.fill(rawBytes, (byte) 0));
    }

    private JwkPublic buildPublicJwk(KeyPair keyPair, KeyAlgorithm algorithm) {
        switch (algorithm) {
            case ES256 -> {
                return buildEcPublicJwk((ECPublicKey) keyPair.getPublic(), algorithm, 32);
            }
            case ES384 -> {
                return buildEcPublicJwk((ECPublicKey) keyPair.getPublic(), algorithm, 48);
            }
            case EdDSA -> {
                return buildEdPublicJwk(keyPair.getPublic().getEncoded());
            }
            default -> throw new IllegalArgumentException(
                    "Unsupported algorithm: " + algorithm);
        }
    }

    private JwkPublic buildEcPublicJwk(
            ECPublicKey ecPublicKey, KeyAlgorithm algorithm, int keySize) {
        byte[] x = toUnsignedBytes(ecPublicKey.getW().getAffineX(), keySize);
        byte[] y = toUnsignedBytes(ecPublicKey.getW().getAffineY(), keySize);
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("kty", "EC");
        claims.put("crv", algorithm.getCurveName());
        claims.put("x", Base64.getUrlEncoder().withoutPadding().encodeToString(x));
        claims.put("y", Base64.getUrlEncoder().withoutPadding().encodeToString(y));
        return new JwkPublic(claims);
    }

    private JwkPublic buildEdPublicJwk(byte[] spkiEncoded) {
        // SubjectPublicKeyInfo for Ed25519: the public key is always the last 32 bytes
        byte[] rawX = Arrays.copyOfRange(spkiEncoded, spkiEncoded.length - 32, spkiEncoded.length);
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("kty", "OKP");
        claims.put("crv", "Ed25519");
        claims.put("x", Base64.getUrlEncoder().withoutPadding().encodeToString(rawX));
        return new JwkPublic(claims);
    }

    private PrivateKey reconstructPrivateKey(byte[] rawBytes, KeyAlgorithm algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        switch (algorithm) {
            case ES256 -> {
                return reconstructEcPrivateKey(rawBytes, "P-256");
            }
            case ES384 -> {
                return reconstructEcPrivateKey(rawBytes, "P-384");
            }
            case EdDSA -> {
                return reconstructEd25519PrivateKey(rawBytes);
            }
            default -> throw new IllegalArgumentException(
                    "Unsupported algorithm: " + algorithm);
        }
    }

    private PrivateKey reconstructEcPrivateKey(byte[] rawBytes, String curveName)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        // Obtain EC parameters for the named curve via a fresh key-pair generator
        KeyPairGenerator gen;
        try {
            gen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            gen.initialize(new ECGenParameterSpec(curveName));
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Cannot initialise EC params for curve: " + curveName, e);
        }
        KeyPair dummy = gen.generateKeyPair();
        ECPrivateKey dummyEcKey = (ECPrivateKey) dummy.getPrivate();
        ECPrivateKeySpec spec = new ECPrivateKeySpec(
                new BigInteger(1, rawBytes),
                dummyEcKey.getParams()
        );
        KeyFactory kf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        return kf.generatePrivate(spec);
    }

    private PrivateKey reconstructEd25519PrivateKey(byte[] seedBytes)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        // Construct PKCS#8 DER from the 32-byte seed by prepending the known prefix
        byte[] pkcs8 = new byte[ED25519_PKCS8_PREFIX.length + seedBytes.length];
        System.arraycopy(ED25519_PKCS8_PREFIX, 0, pkcs8, 0, ED25519_PKCS8_PREFIX.length);
        System.arraycopy(seedBytes, 0, pkcs8, ED25519_PKCS8_PREFIX.length, seedBytes.length);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8);
        KeyFactory kf = KeyFactory.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
        return kf.generatePrivate(spec);
    }

    /**
     * Converts a {@link BigInteger} to an unsigned big-endian byte array of exactly
     * {@code length} bytes. Leading zero bytes from {@link BigInteger#toByteArray()} are
     * stripped; result is zero-padded on the left if shorter than {@code length}.
     */
    private static byte[] toUnsignedBytes(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        // BigInteger.toByteArray() may include a leading 0x00 sign byte
        int start = (raw.length > length) ? raw.length - length : 0;
        int available = raw.length - start;
        byte[] result = new byte[length];
        System.arraycopy(raw, start, result, length - available, available);
        return result;
    }
}