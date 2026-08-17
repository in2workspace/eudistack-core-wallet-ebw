package com.eudistack.ebw.infrastructure.configuration;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.flyway.FlywayProperties;
import org.springframework.boot.autoconfigure.r2dbc.R2dbcProperties;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TenantSchemaFlywayMigratorTest {

    @Test
    void sanitizeSchemaName_shouldAllowValidNames() {
        TenantSchemaFlywayMigrator migrator = new TenantSchemaFlywayMigrator(new FlywayProperties(), new R2dbcProperties());

        assertDoesNotThrow(() -> {
            invokeSanitizeSchemaName(migrator, "tenant1");
            invokeSanitizeSchemaName(migrator, "tenant-1");
            invokeSanitizeSchemaName(migrator, "t123");
        });
    }

    @Test
    void sanitizeSchemaName_shouldThrowExceptionForInvalidNames() {
        TenantSchemaFlywayMigrator migrator = new TenantSchemaFlywayMigrator(new FlywayProperties(), new R2dbcProperties());

        assertThrows(IllegalArgumentException.class, () -> invokeSanitizeSchemaName(migrator, "TENANT")); // No upper case allowed now
        assertThrows(IllegalArgumentException.class, () -> invokeSanitizeSchemaName(migrator, "_tenant")); // Must start with alphanumeric
        assertThrows(IllegalArgumentException.class, () -> invokeSanitizeSchemaName(migrator, "tenant; DROP TABLE users;"));
        assertThrows(IllegalArgumentException.class, () -> invokeSanitizeSchemaName(migrator, "tenant space"));
        assertThrows(IllegalArgumentException.class, () -> invokeSanitizeSchemaName(migrator, "tenant'"));
        assertThrows(IllegalArgumentException.class, () -> invokeSanitizeSchemaName(migrator, "tenant\""));
        assertThrows(IllegalArgumentException.class, () -> invokeSanitizeSchemaName(migrator, "a".repeat(64)));
    }

    private void invokeSanitizeSchemaName(TenantSchemaFlywayMigrator migrator, String schema) throws Exception {
        java.lang.reflect.Method method = TenantSchemaFlywayMigrator.class.getDeclaredMethod("sanitizeSchemaName", String.class);
        method.setAccessible(true);
        try {
            method.invoke(migrator, schema);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof Exception) {
                throw (Exception) e.getCause();
            }
            throw e;
        }
    }
}
