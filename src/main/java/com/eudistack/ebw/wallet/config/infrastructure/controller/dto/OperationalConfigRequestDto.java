package com.eudistack.ebw.wallet.config.infrastructure.controller.dto;

import com.eudistack.ebw.wallet.config.application.operational.ApplyOperationalConfigCommand;
import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
import com.eudistack.ebw.wallet.config.domain.model.operational.DbTdeOperationalConfig;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.Optional;

/**
 * HTTP request body for {@code POST/PUT /business-wallet/admin/wallet-operational-config}.
 *
 * <p>The {@code wrapped_dek} field carries the ciphertext produced by
 * {@code kms:GenerateDataKey} on the operator's workstation (AD-S3 — client-side envelope).
 * Jackson deserialises it from a base64 string into a {@code byte[]} via the standard
 * {@code @JsonProperty} mechanism (Spring Boot auto-configures the Jackson base64 codec).
 *
 * <p>Security invariants:
 * <ul>
 *   <li>{@link #toString()} excludes {@code wrappedDek} — the field name itself may appear
 *       in validation error messages, but its value must never be serialised to logs.</li>
 *   <li>There is no {@code @JsonGetter} or {@code toJSON()} that would expose the field
 *       value in a response body.</li>
 * </ul>
 *
 * <p>Immutable record — Jackson deserialises via the canonical constructor.
 */
public record OperationalConfigRequestDto(
        @JsonProperty("key_manager")
        @NotBlank(message = "key_manager must not be blank")
        String keyManager,

        @JsonProperty("column_encryption_key_arn")
        @NotBlank(message = "column_encryption_key_arn must not be blank")
        String columnEncryptionKeyArn,

        @JsonProperty("wrapped_dek")
        @NotNull(message = "wrapped_dek must not be null")
        @Size(min = 1, message = "wrapped_dek must contain at least one byte")
        byte[] wrappedDek,

        @JsonProperty("algorithm")
        @NotBlank(message = "algorithm must not be blank")
        String algorithm
) {

    /**
     * Builds an {@link ApplyOperationalConfigCommand} from this DTO.
     *
     * <p>The {@code key_manager} string is resolved to a {@link KeyManager} enum via
     * {@link KeyManager#fromValue(String)} (kebab-case — e.g. {@code "db-tde"}).
     * The {@link DbTdeOperationalConfig} compact constructor validates the ARN format,
     * {@code wrappedDek} length, and algorithm name — an {@link IllegalArgumentException}
     * propagates to the controller exception handler, which maps it to HTTP 400.
     *
     * @param actor          the PBAC subject resolved from the security context (non-blank)
     * @param correlationId  the W3C trace-id from {@code X-Correlation-Id} header, or a UUID v4
     * @param ifMatchVersion empty for POST (create), present for PUT (update with optimistic lock)
     * @return a fully-populated command
     */
    public ApplyOperationalConfigCommand toCommand(
            String actor,
            String correlationId,
            Optional<Long> ifMatchVersion) {
        KeyManager resolvedKeyManager = KeyManager.fromValue(keyManager);
        DbTdeOperationalConfig operationalConfig = new DbTdeOperationalConfig(
                columnEncryptionKeyArn,
                wrappedDek,
                algorithm
        );
        return new ApplyOperationalConfigCommand(
                resolvedKeyManager,
                operationalConfig,
                actor,
                correlationId,
                ifMatchVersion
        );
    }

    /**
     * Overrides the default record {@code toString()} to exclude {@code wrappedDek}.
     *
     * <p>The field name may appear (e.g. in validation errors), but the byte array value
     * is never emitted to logs or traces (AC-2b).
     */
    @Override
    public String toString() {
        return "OperationalConfigRequestDto{"
                + "keyManager='" + keyManager + '\''
                + ", columnEncryptionKeyArn='" + columnEncryptionKeyArn + '\''
                + ", wrappedDek=<redacted>"
                + ", algorithm='" + algorithm + '\''
                + '}';
    }
}
