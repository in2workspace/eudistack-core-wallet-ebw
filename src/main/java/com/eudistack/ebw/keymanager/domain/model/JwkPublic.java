package com.eudistack.ebw.keymanager.domain.model;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Immutable value object representing a public JWK (JSON Web Key).
 *
 * <p>Wraps a {@code Map<String, Object>} that contains the standard JWK members
 * ({@code kty}, {@code crv}, {@code x}, and optionally {@code y} for EC keys).
 * The map is stored as-is and assumed to be unmodifiable after construction.</p>
 *
 * <p>The {@link #jkt()} method computes the JWK Thumbprint per RFC 7638 §3:
 * SHA-256 over the canonical JSON of the required members (lexicographically sorted keys),
 * Base64url-encoded without padding.</p>
 *
 * <p>Required members per key type:</p>
 * <ul>
 *   <li>EC keys (ES256, ES384): {@code crv}, {@code kty}, {@code x}, {@code y}</li>
 *   <li>OKP keys (EdDSA): {@code crv}, {@code kty}, {@code x}</li>
 * </ul>
 *
 * <p>Spec: RFC 7638 §3 (JWK Thumbprint), RFC 7517 (JWK), RFC 7518 §6 (key types).</p>
 */
public record JwkPublic(Map<String, Object> claims) {

    public JwkPublic {
        Objects.requireNonNull(claims, "JwkPublic claims must not be null");
        if (claims.isEmpty()) {
            throw new IllegalArgumentException("JwkPublic claims must not be empty");
        }
    }

    /**
     * Computes the JWK Thumbprint (RFC 7638 §3) of this public key.
     *
     * <p>Algorithm:</p>
     * <ol>
     *   <li>Select the required members from the JWK based on {@code kty} and {@code crv}.</li>
     *   <li>Sort the selected members lexicographically by key name.</li>
     *   <li>Serialize the resulting object to UTF-8 JSON without whitespace.</li>
     *   <li>Compute SHA-256 of the serialized bytes.</li>
     *   <li>Return the Base64url-encoded result without padding.</li>
     * </ol>
     *
     * @return the JWK Thumbprint as a Base64url string (no padding)
     * @throws IllegalStateException if serialization or hashing fails
     */
    public String jkt() {
        try {
            String kty = (String) claims.get("kty");
            String crv = (String) claims.get("crv");

            TreeMap<String, Object> requiredMembers = buildRequiredMembers(kty, crv);

            ObjectMapper mapper = new ObjectMapper();
            byte[] canonical = mapper.writeValueAsBytes(requiredMembers);

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] digest = sha256.digest(canonical);

            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated by Java SE — this path is unreachable on a compliant JVM
            throw new IllegalStateException("SHA-256 not available", e);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute JWK Thumbprint", e);
        }
    }

    /**
     * Builds the required-members map for thumbprint computation per RFC 7638 §3.
     *
     * <p>For EC keys ({@code kty=EC}): required = {@code crv}, {@code kty}, {@code x}, {@code y}.
     * For OKP keys ({@code kty=OKP}): required = {@code crv}, {@code kty}, {@code x}.</p>
     */
    private TreeMap<String, Object> buildRequiredMembers(String kty, String crv) {
        TreeMap<String, Object> required = new TreeMap<>();
        required.put("crv", Objects.requireNonNull(crv, "JWK 'crv' member is required for thumbprint"));
        required.put("kty", Objects.requireNonNull(kty, "JWK 'kty' member is required for thumbprint"));
        required.put("x", Objects.requireNonNull(claims.get("x"), "JWK 'x' member is required for thumbprint"));

        if ("EC".equals(kty)) {
            required.put("y", Objects.requireNonNull(claims.get("y"), "JWK 'y' member is required for EC thumbprint"));
        }
        // OKP (Ed25519) uses only crv, kty, x — no y member

        return required;
    }
}