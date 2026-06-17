package com.eudistack.ebw.keymanager.domain.model;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

/**
 * Domain aggregate representing the AES-256-GCM-wrapped holder private key stored per
 * {@code (tenantId, holderId, credentialId)} tuple.
 *
 * <p>Security constraints (AC-02, AC-03, NFR-04):
 * <ul>
 *   <li>{@code wrappedBlob} is opaque ciphertext — never in plaintext on the server.</li>
 *   <li>{@code iv} is 12 bytes (AES-GCM nonce), unique per wrap operation.</li>
 *   <li>{@code tag} is 16 bytes (AES-GCM authentication tag).</li>
 *   <li>Together {@code wrappedBlob + iv + tag} are non-reconstructable without the
 *       holder's passkey (PRF output), so a {@code pg_dump} cannot recover the key.</li>
 * </ul>
 *
 * <p>{@link #toString()} redacts {@code wrappedBlob}, {@code iv}, and {@code tag} to
 * prevent accidental exposure in logs (NFR-06).</p>
 *
 * <p>Spec: EUDISTACK-534 AC-02, AC-03, AC-04, AC-05; architecture.md §5.3.</p>
 */
public record WrappedKeyHandle(
        String tenantId,
        String holderId,
        String credentialId,
        byte[] wrappedBlob,
        byte[] iv,
        byte[] tag,
        String kdfAlgo,
        int kdfVersion,
        String cnfJwk,
        Instant createdAt,
        Instant lastUsedAt
) {

    public WrappedKeyHandle {
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        if (tenantId.isBlank()) throw new IllegalArgumentException("tenantId must not be blank");
        Objects.requireNonNull(holderId, "holderId must not be null");
        if (holderId.isBlank()) throw new IllegalArgumentException("holderId must not be blank");
        Objects.requireNonNull(credentialId, "credentialId must not be null");
        if (credentialId.isBlank()) throw new IllegalArgumentException("credentialId must not be blank");
        Objects.requireNonNull(wrappedBlob, "wrappedBlob must not be null");
        if (wrappedBlob.length < 48) throw new IllegalArgumentException("wrappedBlob must be at least 48 bytes");
        Objects.requireNonNull(iv, "iv must not be null");
        if (iv.length != 12) throw new IllegalArgumentException("iv must be exactly 12 bytes");
        Objects.requireNonNull(tag, "tag must not be null");
        if (tag.length != 16) throw new IllegalArgumentException("tag must be exactly 16 bytes");
        Objects.requireNonNull(kdfAlgo, "kdfAlgo must not be null");
        if (kdfAlgo.isBlank()) throw new IllegalArgumentException("kdfAlgo must not be blank");
        Objects.requireNonNull(cnfJwk, "cnfJwk must not be null");
        if (cnfJwk.isBlank()) throw new IllegalArgumentException("cnfJwk must not be blank");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        // lastUsedAt is nullable — null until the holder first signs
        wrappedBlob = wrappedBlob.clone();
        iv = iv.clone();
        tag = tag.clone();
    }

    @Override
    public byte[] wrappedBlob() { return wrappedBlob.clone(); }

    @Override
    public byte[] iv() { return iv.clone(); }

    @Override
    public byte[] tag() { return tag.clone(); }

    /** Returns true if {@code other} carries identical ciphertext (same blob, iv, and tag). */
    public boolean blobEquals(WrappedKeyHandle other) {
        return Arrays.equals(wrappedBlob, other.wrappedBlob)
                && Arrays.equals(iv, other.iv)
                && Arrays.equals(tag, other.tag);
    }

    /** Redacts sensitive byte arrays to prevent accidental log exposure (NFR-06). */
    @Override
    public String toString() {
        return "WrappedKeyHandle["
                + "tenantId=" + tenantId
                + ", holderId=" + holderId
                + ", credentialId=" + credentialId
                + ", wrappedBlob=[REDACTED]"
                + ", iv=[REDACTED]"
                + ", tag=[REDACTED]"
                + ", kdfAlgo=" + kdfAlgo
                + ", kdfVersion=" + kdfVersion
                + ", createdAt=" + createdAt
                + ", lastUsedAt=" + lastUsedAt
                + "]";
    }
}