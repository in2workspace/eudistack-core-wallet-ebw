package com.eudistack.ebw.infrastructure.configuration;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.configuration.FluentConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.mockito.MockedStatic;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.autoconfigure.flyway.FlywayProperties;
import org.springframework.boot.autoconfigure.r2dbc.R2dbcProperties;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class TenantSchemaFlywayMigratorTest {

    private FlywayProperties flywayProperties;
    private R2dbcProperties r2dbcProperties;
    private TenantSchemaFlywayMigrator migrator;
    private MockedStatic<Flyway> flywayMock;
    private MockedStatic<DriverManager> driverManagerMock;
    private FluentConfiguration fluentConfiguration;
    private Flyway flyway;

    @BeforeEach
    void setUp() {
        flywayProperties = mock(FlywayProperties.class);
        r2dbcProperties = mock(R2dbcProperties.class);
        migrator = new TenantSchemaFlywayMigrator(flywayProperties, r2dbcProperties);

        flywayMock = mockStatic(Flyway.class);
        driverManagerMock = mockStatic(DriverManager.class);

        fluentConfiguration = mock(FluentConfiguration.class, Answers.RETURNS_SELF);
        flywayMock.when(Flyway::configure).thenReturn(fluentConfiguration);
        
        flyway = mock(Flyway.class);
        when(fluentConfiguration.load()).thenReturn(flyway);
    }

    @AfterEach
    void tearDown() {
        flywayMock.close();
        driverManagerMock.close();
    }

    @Test
    void run_shouldMigratePublicAndTenants() throws Exception {
        when(flywayProperties.getUrl()).thenReturn("jdbc:postgresql://localhost:5432/db");
        when(r2dbcProperties.getUsername()).thenReturn("user");
        when(r2dbcProperties.getPassword()).thenReturn("pass");

        Connection conn = mock(Connection.class);
        PreparedStatement stmt = mock(PreparedStatement.class);
        ResultSet rs = mock(ResultSet.class);

        driverManagerMock.when(() -> DriverManager.getConnection("jdbc:postgresql://localhost:5432/db", "user", "pass"))
                .thenReturn(conn);
        when(conn.prepareStatement(anyString())).thenReturn(stmt);
        when(stmt.executeQuery()).thenReturn(rs);
        when(rs.next()).thenReturn(true, false); // Un solo inquilino
        when(rs.getString("schema_name")).thenReturn("tenant1");

        migrator.run(mock(ApplicationArguments.class));

        // Verificar migración de esquema público
        verify(fluentConfiguration).defaultSchema("public");
        verify(fluentConfiguration).schemas("public");

        // Verificar migración de esquema de inquilino
        // Suffix is _business_wallet
        String expectedTenantSchema = "tenant1_business_wallet";
        verify(fluentConfiguration).defaultSchema(expectedTenantSchema);
        verify(fluentConfiguration).schemas(expectedTenantSchema);

        verify(flyway, atLeast(2)).migrate();
    }

    @Test
    void loadActiveTenants_shouldReturnEmptyListOnException() throws Exception {
        when(flywayProperties.getUrl()).thenReturn("jdbc:postgresql://localhost:5432/db");
        when(r2dbcProperties.getUsername()).thenReturn("user");
        when(r2dbcProperties.getPassword()).thenReturn("pass");

        driverManagerMock.when(() -> DriverManager.getConnection(anyString(), anyString(), anyString()))
                .thenThrow(new RuntimeException("Connection error"));

        java.lang.reflect.Method method = TenantSchemaFlywayMigrator.class.getDeclaredMethod("loadActiveTenants", String.class, String.class, String.class);
        method.setAccessible(true);
        List<String> tenants = (List<String>) method.invoke(migrator, "jdbc:postgresql://localhost:5432/db", "user", "pass");

        assertTrue(tenants.isEmpty());
    }

    @Test
    void sanitizeSchemaName_shouldAllowValidNames() {
        assertDoesNotThrow(() -> invokeSanitizeSchemaName(migrator, "tenant1"));
        assertDoesNotThrow(() -> invokeSanitizeSchemaName(migrator, "tenant-1"));
        assertDoesNotThrow(() -> invokeSanitizeSchemaName(migrator, "t123"));
    }

    @Test
    void sanitizeSchemaName_shouldThrowExceptionForInvalidNames() {
        assertThrows(IllegalArgumentException.class, () -> invokeSanitizeSchemaName(migrator, null));
        assertThrows(IllegalArgumentException.class, () -> invokeSanitizeSchemaName(migrator, "TENANT"));
        assertThrows(IllegalArgumentException.class, () -> invokeSanitizeSchemaName(migrator, "_tenant"));
        
        String longSchema = "a".repeat(64);
        assertThrows(IllegalArgumentException.class, () -> invokeSanitizeSchemaName(migrator, longSchema));
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
