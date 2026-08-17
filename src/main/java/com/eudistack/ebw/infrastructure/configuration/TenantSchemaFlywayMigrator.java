package com.eudistack.ebw.infrastructure.configuration;

import lombok.extern.slf4j.Slf4j;
import org.flywaydb.core.Flyway;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.flyway.FlywayProperties;
import org.springframework.boot.autoconfigure.r2dbc.R2dbcProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
@Order(1)
@EnableConfigurationProperties({R2dbcProperties.class, FlywayProperties.class})
public class TenantSchemaFlywayMigrator implements ApplicationRunner {

    private static final String SCHEMA_SUFFIX = TenantAwareConnectionFactoryDecorator.SCHEMA_SUFFIX;

    private final FlywayProperties flywayProperties;
    private final R2dbcProperties r2dbcProperties;

    public TenantSchemaFlywayMigrator(FlywayProperties flywayProperties, R2dbcProperties r2dbcProperties) {
        this.flywayProperties = flywayProperties;
        this.r2dbcProperties = r2dbcProperties;
    }

    @Override
    public void run(ApplicationArguments args) {
        String jdbcUrl = flywayProperties.getUrl();
        String username = r2dbcProperties.getUsername();
        String password = r2dbcProperties.getPassword();

        migratePublicSchema(jdbcUrl, username, password);

        List<String> tenants = loadActiveTenants(jdbcUrl, username, password);
        for (String tenant : tenants) {
            migrateTenantSchema(jdbcUrl, username, password, tenant + SCHEMA_SUFFIX);
        }

        log.info("Flyway multi-schema migration completed: public + {} tenant schemas (suffix '{}')",
                tenants.size(), SCHEMA_SUFFIX);
    }

    private void migratePublicSchema(String jdbcUrl, String username, String password) {
        log.info("Migrating public schema...");
        Flyway.configure()
                .dataSource(jdbcUrl, username, password)
                .locations("classpath:db/migration")
                .defaultSchema("public")
                .schemas("public")
                .baselineOnMigrate(true)
                .load()
                .migrate();
    }

    private List<String> loadActiveTenants(String jdbcUrl, String username, String password) {
        List<String> tenants = new ArrayList<>();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, username, password);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(
                     "SELECT schema_name FROM public.tenant_registry WHERE status = 'active'")) {
            while (rs.next()) {
                tenants.add(rs.getString("schema_name"));
            }
        } catch (Exception e) {
            log.warn("Could not load tenants from tenant_registry: {}. " +
                    "This is expected on first run before tenant_registry exists.", e.getMessage());
        }
        log.info("Found {} active tenants: {}", tenants.size(), tenants);
        return tenants;
    }

    private void migrateTenantSchema(String jdbcUrl, String username, String password, String schema) {
        log.info("Migrating tenant schema: {}", schema);
        String validatedSchema = sanitizeSchemaName(schema);
        try (Connection conn = DriverManager.getConnection(jdbcUrl, username, password);
             Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE SCHEMA IF NOT EXISTS \"" + validatedSchema + "\"");
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create schema: " + schema, e);
        }

        Flyway.configure()
                .dataSource(jdbcUrl, username, password)
                .locations("classpath:db/tenant")
                .defaultSchema(validatedSchema)
                .schemas(validatedSchema)
                .table("flyway_schema_history")
                .baselineOnMigrate(true)
                .load()
                .migrate();
    }

    private String sanitizeSchemaName(String schema) {
        if (schema == null || !schema.matches("^[a-z0-9][a-z0-9_-]{0,62}$")) {
            throw new IllegalArgumentException("Invalid schema name: " + schema);
        }
        return schema;
    }
}
