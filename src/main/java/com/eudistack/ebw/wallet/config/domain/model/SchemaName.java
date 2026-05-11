package com.eudistack.ebw.wallet.config.domain.model;

import java.util.regex.Pattern;

/**
 * Validation helper for PostgreSQL schema-name identifiers used as tenant keys.
 *
 * <p>A valid schema name is a strict lowercase PostgreSQL identifier:
 * starts with a letter, contains only lowercase letters, digits and underscores,
 * and is at most 63 characters long ({@code ^[a-z][a-z0-9_]{0,62}$}). This matches
 * the {@code @Pattern} on {@code AdminConfigRequestDto.schemaName} and the
 * {@code tenant_registry.schema_name VARCHAR(64)} column.
 *
 * <p>This guard MUST be applied at any boundary where a {@code schemaName} is interpolated
 * into a SQL identifier (e.g. a schema-qualified table name) — relying on a single upstream
 * Bean Validation annotation is not sufficient to protect an injection sink (SEC-B1).
 */
public final class SchemaName {

    /** Strict PostgreSQL identifier pattern: lowercase, starts with a letter, max 63 chars. */
    public static final Pattern PATTERN = Pattern.compile("^[a-z][a-z0-9_]{0,62}$");

    private SchemaName() {
    }

    /**
     * Returns {@code schemaName} unchanged if it is a valid PostgreSQL identifier, otherwise
     * throws {@link IllegalArgumentException} (mapped to HTTP 400 by the global handler).
     *
     * @param schemaName the candidate schema name
     * @return the validated schema name
     * @throws IllegalArgumentException if {@code schemaName} is null, empty, or does not match
     *                                  {@link #PATTERN}
     */
    public static String requireValid(String schemaName) {
        if (schemaName == null || !PATTERN.matcher(schemaName).matches()) {
            throw new IllegalArgumentException(
                    "schema_name must be a valid PostgreSQL identifier "
                            + "(lowercase, starts with a letter, max 63 chars): " + schemaName);
        }
        return schemaName;
    }
}
