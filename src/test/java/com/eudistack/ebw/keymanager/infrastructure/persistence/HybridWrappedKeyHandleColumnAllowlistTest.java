package com.eudistack.ebw.keymanager.infrastructure.persistence;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Static CI guard: verifies that {@code V4__create_hybrid_wrapped_key_handle.sql}
 * contains no column names that suggest holder private key material or wrap key
 * in clear (NFR-S-535-02, AD-2).
 *
 * <p>This test does not require a database. It parses the SQL migration file
 * at test-classpath resolution time and compares every declared column name
 * against a deny-list of suspicious patterns. A future migration that accidentally
 * adds a column like {@code private_key_plain} or {@code wrap_key} will be caught
 * here in every CI build (R-3 mitigation).
 *
 * <p>The test also asserts that the expected allow-listed columns are present
 * in the DDL, so a column rename that would break the no-custody guarantee
 * would surface immediately.
 *
 * <p>Spec: EUDISTACK-535 T3; acceptance-criteria.md AC-03; NFR-S-535-02;
 * technical-design.md §3.5 AD-2.
 */
class HybridWrappedKeyHandleColumnAllowlistTest {

    /**
     * Path to the migration file inside the test classpath.
     * Loaded from {@code src/main/resources/db/tenant/} which is on the test classpath.
     */
    private static final String MIGRATION_CLASSPATH =
            "db/tenant/V4__create_hybrid_wrapped_key_handle.sql";

    /**
     * Columns allowed in {@code hybrid_wrapped_key_handle}.
     * Any column NOT in this list triggers a test failure.
     *
     * <p>Note: {@code cnf_jwk} is included here because US-02 (EUDISTACK-534) added it
     * to {@code WrappedKeyHandleRow} before US-03 merged; the column stores a public
     * confirmation JWK (not a private key). Spec gap documented in the migration header.
     */
    private static final List<String> ALLOW_LIST = List.of(
            "holder_id",
            "credential_id",
            "wrapped_blob",
            "iv",
            "tag",
            "kdf_algo",
            "kdf_version",
            "cnf_jwk",
            "created_at",
            "last_used_at"
    );

    /**
     * Patterns that must never appear as a column name (case-insensitive).
     * Covers: plaintext key material, wrap key, private key, secret, raw key bytes.
     */
    private static final List<Pattern> DENY_PATTERNS = List.of(
            Pattern.compile(".*_plain.*",       Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*plain_.*",       Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*private_key.*",  Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*wrap_key.*",     Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*wrapkey.*",      Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*secret.*",       Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*raw_key.*",      Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*cleartext.*",    Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*plaintext.*",    Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*private.*",      Pattern.CASE_INSENSITIVE)
    );

    /**
     * Regex that matches a column definition line inside a CREATE TABLE block.
     * Captures the column name (first identifier on the line, excluding constraint keywords).
     *
     * <p>Matches lines of the form:
     * {@code     column_name   TYPE   [NOT NULL] [...],}
     *
     * <p>Constraint lines (starting with CONSTRAINT, PRIMARY, FOREIGN, CHECK, UNIQUE)
     * are excluded by the negative-lookahead.
     */
    private static final Pattern COLUMN_LINE = Pattern.compile(
            "^\\s+(?!CONSTRAINT|PRIMARY|FOREIGN|CHECK|UNIQUE)([a-zA-Z_][a-zA-Z0-9_]*)\\s+",
            Pattern.MULTILINE
    );

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    @Test
    void migration_file_exists_and_is_readable() throws IOException {
        String sql = readMigrationSql();
        assertThat(sql)
                .as("Migration file %s must exist and be non-empty", MIGRATION_CLASSPATH)
                .isNotBlank();
        assertThat(sql)
                .as("Migration must create hybrid_wrapped_key_handle table")
                .contains("hybrid_wrapped_key_handle");
    }

    @Test
    void migration_columns_are_within_allow_list() throws IOException {
        String sql = readMigrationSql();
        List<String> detectedColumns = extractColumnNames(sql);

        assertThat(detectedColumns)
                .as("No columns were detected in the DDL — check the migration file format")
                .isNotEmpty();

        for (String column : detectedColumns) {
            assertThat(ALLOW_LIST)
                    .as("Column '%s' is not in the allow-list. "
                        + "If this is a new legitimate column, add it to ALLOW_LIST "
                        + "and have a Security Lead review the migration (NFR-S-535-02).",
                        column)
                    .contains(column);
        }
    }

    @Test
    void migration_columns_match_no_deny_pattern() throws IOException {
        String sql = readMigrationSql();
        List<String> detectedColumns = extractColumnNames(sql);

        for (String column : detectedColumns) {
            for (Pattern denied : DENY_PATTERNS) {
                assertThat(denied.matcher(column).matches())
                        .as("Column '%s' matches deny-pattern '%s'. "
                            + "Columns must never store holder private key material or wrap key in clear "
                            + "(NFR-S-535-02, AD-2, EUDISTACK-535).",
                            column, denied.pattern())
                        .isFalse();
            }
        }
    }

    @Test
    void migration_contains_all_expected_columns() throws IOException {
        String sql = readMigrationSql();
        List<String> detectedColumns = extractColumnNames(sql);

        List<String> expectedDataColumns = List.of(
                "holder_id", "credential_id",
                "wrapped_blob", "iv", "tag",
                "kdf_algo", "kdf_version",
                "cnf_jwk",
                "created_at", "last_used_at"
        );

        for (String expected : expectedDataColumns) {
            assertThat(detectedColumns)
                    .as("Expected column '%s' was not found in the DDL "
                        + "(technical-design.md §3.2.1)", expected)
                    .contains(expected);
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private String readMigrationSql() throws IOException {
        try (InputStream is = getClass().getClassLoader()
                .getResourceAsStream(MIGRATION_CLASSPATH)) {
            assertThat(is)
                    .as("Migration resource '%s' not found on classpath", MIGRATION_CLASSPATH)
                    .isNotNull();
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /**
     * Extracts column names from the CREATE TABLE block in the SQL file.
     * Only picks up actual column definitions; skips constraint declarations.
     */
    private List<String> extractColumnNames(String sql) {
        List<String> columns = new ArrayList<>();
        Matcher matcher = COLUMN_LINE.matcher(sql);
        while (matcher.find()) {
            String name = matcher.group(1).toLowerCase();
            // Skip SQL keywords that can appear at line-start (defensive)
            if (!isSqlKeyword(name)) {
                columns.add(name);
            }
        }
        return columns;
    }

    private boolean isSqlKeyword(String name) {
        return switch (name.toUpperCase()) {
            case "CREATE", "ALTER", "DROP", "INSERT", "UPDATE", "DELETE",
                 "SELECT", "FROM", "WHERE", "TABLE", "INDEX", "GRANT", "REVOKE",
                 "DO", "BEGIN", "END", "EXCEPTION", "WHEN", "THEN", "NULL",
                 "IF", "NOT", "EXISTS", "REFERENCES", "ON", "SET" -> true;
            default -> false;
        };
    }
}
