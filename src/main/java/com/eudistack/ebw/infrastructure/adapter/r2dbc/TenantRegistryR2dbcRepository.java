package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.repository.TenantRegistryRepository;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public class TenantRegistryR2dbcRepository implements TenantRegistryRepository {

    private static final String FIND_DISPLAY_NAME_SQL =
            "SELECT display_name FROM public.tenant_registry WHERE schema_name = :tenantId";

    private final DatabaseClient databaseClient;

    public TenantRegistryR2dbcRepository(DatabaseClient databaseClient) {
        this.databaseClient = databaseClient;
    }

    @Override
    public Mono<String> findDisplayName(String tenantId) {
        return databaseClient.sql(FIND_DISPLAY_NAME_SQL)
                .bind("tenantId", tenantId)
                .map(row -> row.get("display_name", String.class))
                .one();
    }
}
