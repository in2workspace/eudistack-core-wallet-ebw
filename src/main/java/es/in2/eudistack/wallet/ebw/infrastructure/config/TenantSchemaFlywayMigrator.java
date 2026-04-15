package es.in2.eudistack.wallet.ebw.infrastructure.config;

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

        List<String> tenantSchemas = loadActiveTenantSchemas(jdbcUrl, username, password);
        for (String schema : tenantSchemas) {
            migrateTenantSchema(jdbcUrl, username, password, schema);
        }

        log.info("EBW Flyway multi-schema migration completed: public + {} tenant schemas", tenantSchemas.size());
    }

    private void migratePublicSchema(String jdbcUrl, String username, String password) {
        log.info("EBW: Migrating public schema...");
        Flyway.configure()
                .dataSource(jdbcUrl, username, password)
                .locations("classpath:db/migration")
                .defaultSchema("public")
                .schemas("public")
                .baselineOnMigrate(true)
                .load()
                .migrate();
    }

    private List<String> loadActiveTenantSchemas(String jdbcUrl, String username, String password) {
        List<String> schemas = new ArrayList<>();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, username, password);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(
                     "SELECT schema_name FROM public.tenant_registry WHERE status = 'active'")) {
            while (rs.next()) {
                schemas.add(rs.getString("schema_name"));
            }
        } catch (Exception e) {
            log.warn("EBW: Could not load tenant schemas: {}. Expected on first run.", e.getMessage());
        }
        log.info("EBW: Found {} active tenant schemas: {}", schemas.size(), schemas);
        return schemas;
    }

    private void migrateTenantSchema(String jdbcUrl, String username, String password, String schema) {
        log.info("EBW: Migrating tenant schema: {}", schema);
        try (Connection conn = DriverManager.getConnection(jdbcUrl, username, password);
             Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE SCHEMA IF NOT EXISTS " + sanitizeSchemaName(schema));
        } catch (Exception e) {
            throw new IllegalStateException("EBW: Failed to create schema: " + schema, e);
        }

        Flyway.configure()
                .dataSource(jdbcUrl, username, password)
                .locations("classpath:db/tenant")
                .defaultSchema(schema)
                .schemas(schema)
                .table("flyway_schema_history")
                .baselineOnMigrate(true)
                .load()
                .migrate();
    }

    private String sanitizeSchemaName(String schema) {
        if (!schema.matches("^[a-zA-Z0-9_-]+$")) {
            throw new IllegalArgumentException("Invalid schema name: " + schema);
        }
        return schema;
    }
}
