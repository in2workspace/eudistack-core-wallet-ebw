package com.eudistack.ebw.wallet.config.domain.model.operational;

import java.util.Arrays;
import java.util.Objects;

/**
 * Operational configuration for a tenant whose key manager is {@code db-tde}.
 *
 * <p>The data-encryption key (DEK) is stored envelope-encrypted: the {@code wrappedDek} field
 * contains the ciphertext produced by {@code kms:Encrypt} (or {@code kms:GenerateDataKey})
 * against the tenant's KMS CMK. It is never decrypted within the operational-config plane —
 * only the downstream column-encryption consumer calls {@code kms:Decrypt} when it needs the
 * plaintext DEK.
 *
 * <p>Invariants (enforced in compact constructor):
 * <ul>
 *   <li>{@code columnEncryptionKeyArn} must be a well-formed AWS KMS ARN
 *       (starts with {@code arn:aws:kms:}).</li>
 *   <li>{@code wrappedDek} must be non-null and have at least one byte.</li>
 *   <li>{@code algorithm} must equal {@code "AES-256-GCM"} (the only algorithm supported
 *       in the MVP; room for extension in future Stories).</li>
 * </ul>
 *
 * <p>Security properties:
 * <ul>
 *   <li>{@link #toString()} redacts {@code wrappedDek} — it is never printed in full.</li>
 *   <li>{@link #equals} and {@link #hashCode} exclude {@code wrappedDek}. Java records use
 *       array identity ({@code ==}) by default for {@code byte[]} fields; this implementation
 *       overrides both to use only {@code columnEncryptionKeyArn} and {@code algorithm}, which
 *       is intentional — the secret material should not be part of structural equality checks
 *       (AC-2b, E-16).</li>
 * </ul>
 */
public record DbTdeOperationalConfig(
        String columnEncryptionKeyArn,
        byte[] wrappedDek,
        String algorithm
) implements OperationalConfig {

    private static final String REQUIRED_ALGORITHM = "AES-256-GCM";
    private static final String ARN_PREFIX = "arn:aws:kms:";

    /**
     * Compact constructor — validates all invariants before the record is constructed.
     *
     * @throws IllegalArgumentException if any invariant is violated
     */
    public DbTdeOperationalConfig {
        if (columnEncryptionKeyArn == null || !columnEncryptionKeyArn.startsWith(ARN_PREFIX)) {
            throw new IllegalArgumentException(
                    "columnEncryptionKeyArn must be a well-formed AWS KMS ARN "
                            + "(must start with '" + ARN_PREFIX + "')");
        }
        if (wrappedDek == null || wrappedDek.length < 1) {
            throw new IllegalArgumentException(
                    "wrappedDek must be non-null and contain at least one byte");
        }
        if (!REQUIRED_ALGORITHM.equals(algorithm)) {
            throw new IllegalArgumentException(
                    "algorithm must be '" + REQUIRED_ALGORITHM + "', got: " + algorithm);
        }
        // Defensive copy to preserve record immutability for the byte array.
        wrappedDek = Arrays.copyOf(wrappedDek, wrappedDek.length);
    }

    /**
     * Returns a defensive copy of the wrapped DEK to prevent external mutation.
     *
     * <p>Callers must never pass this array to a logger or serialize it to JSON responses.
     */
    @Override
    public byte[] wrappedDek() {
        return Arrays.copyOf(wrappedDek, wrappedDek.length);
    }

    /**
     * Redacts the {@code wrappedDek} field — logs and debug output never expose secret material.
     */
    @Override
    public String toString() {
        return "DbTdeOperationalConfig{"
                + "columnEncryptionKeyArn='" + columnEncryptionKeyArn + '\''
                + ", wrappedDek=<redacted, " + wrappedDek.length + " bytes>"
                + ", algorithm='" + algorithm + '\''
                + '}';
    }

    /**
     * Structural equality based on {@code columnEncryptionKeyArn} and {@code algorithm} only.
     *
     * <p>{@code wrappedDek} is excluded intentionally: comparing byte arrays with
     * {@code Arrays.equals} would expose the secret to timing side-channels in equality checks,
     * and the operational-config domain does not need byte-level comparison of the ciphertext.
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof DbTdeOperationalConfig other)) {
            return false;
        }
        return Objects.equals(columnEncryptionKeyArn, other.columnEncryptionKeyArn)
                && Objects.equals(algorithm, other.algorithm);
    }

    /**
     * Hash code based on {@code columnEncryptionKeyArn} and {@code algorithm} only,
     * consistent with {@link #equals}.
     */
    @Override
    public int hashCode() {
        return Objects.hash(columnEncryptionKeyArn, algorithm);
    }
}
