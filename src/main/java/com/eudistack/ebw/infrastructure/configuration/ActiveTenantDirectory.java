package com.eudistack.ebw.infrastructure.configuration;

import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

/**
 * Active tenants of {@code public.tenant_registry}, the same list
 * {@link TenantSchemaFlywayMigrator} migrates. Queried without tenant in the Reactor context,
 * so the connection's {@code search_path} is {@code public}.
 */
@Component
public class ActiveTenantDirectory {

    private static final String ACTIVE_TENANTS_SQL =
            "SELECT schema_name FROM public.tenant_registry WHERE status = 'active' ORDER BY schema_name";

    private final DatabaseClient databaseClient;

    public ActiveTenantDirectory(DatabaseClient databaseClient) {
        this.databaseClient = databaseClient;
    }

    public Flux<String> activeTenants() {
        return databaseClient.sql(ACTIVE_TENANTS_SQL)
                .map((row, metadata) -> row.get("schema_name", String.class))
                .all();
    }
}
