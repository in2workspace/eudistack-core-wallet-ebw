package com.eudistack.ebw.wallet.config.infrastructure.persistence;

import com.eudistack.ebw.wallet.config.domain.exception.ConfigVersionConflictException;
import com.eudistack.ebw.wallet.config.domain.model.TenantWalletConfigDescriptor;
import com.eudistack.ebw.wallet.config.domain.model.WalletMode;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.WalletTenantConfigR2dbcAdapter;
import io.r2dbc.postgresql.PostgresqlConnectionConfiguration;
import io.r2dbc.postgresql.PostgresqlConnectionFactory;
import io.r2dbc.spi.ConnectionFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.data.r2dbc.core.DefaultReactiveDataAccessStrategy;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.data.r2dbc.dialect.PostgresDialect;
import org.springframework.r2dbc.core.DatabaseClient;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.test.StepVerifier;

import java.util.Collections;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for {@link WalletTenantConfigR2dbcAdapter} against Testcontainers PostgreSQL.
 *
 * <p>Covers the create-vs-update version bump (AC-3a/AC-3b) and the optimistic-lock conflict
 * (W3 / SEC-W3 / E-6): a PUT with a stale {@code expectedVersion} → {@link ConfigVersionConflictException}.
 */
@Testcontainers
@Tag("integration")
class WalletTenantConfigR2dbcAdapterIT {

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("ebw_twc_it")
                    .withUsername("it_user")
                    .withPassword("it_pass");

    private static DatabaseClient dbClient;
    private static R2dbcEntityTemplate template;
    private WalletTenantConfigR2dbcAdapter adapter;

    @BeforeAll
    static void setUpSchema() {
        ConnectionFactory connectionFactory = new PostgresqlConnectionFactory(
                PostgresqlConnectionConfiguration.builder()
                        .host(postgres.getHost())
                        .port(postgres.getMappedPort(5432))
                        .database("ebw_twc_it")
                        .username("it_user")
                        .password("it_pass")
                        .build());

        dbClient = DatabaseClient.create(connectionFactory);
        template = new R2dbcEntityTemplate(dbClient,
                new DefaultReactiveDataAccessStrategy(PostgresDialect.INSTANCE));

        // Mirrors V1__Public_schema.sql + V2__Create_tenant_wallet_config.sql (subset needed here).
        dbClient.sql("CREATE TABLE IF NOT EXISTS public.tenant_registry ("
                + "schema_name VARCHAR(64) PRIMARY KEY, display_name VARCHAR(255) NOT NULL)")
                .then().block();
        dbClient.sql("CREATE TABLE IF NOT EXISTS public.tenant_wallet_config ("
                + "schema_name VARCHAR(64) PRIMARY KEY "
                + "  REFERENCES public.tenant_registry(schema_name) ON DELETE CASCADE, "
                + "host VARCHAR(255) NOT NULL UNIQUE, wallet_mode VARCHAR(50) NOT NULL, "
                + "key_manager VARCHAR(50), natural_persons_only BOOLEAN NOT NULL DEFAULT FALSE, "
                + "version BIGINT NOT NULL DEFAULT 1, updated_by VARCHAR(255), "
                + "updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), "
                + "created_at TIMESTAMPTZ NOT NULL DEFAULT now())")
                .then().block();
        dbClient.sql("INSERT INTO public.tenant_registry(schema_name, display_name) "
                + "VALUES ('acme', 'Acme') ON CONFLICT DO NOTHING")
                .then().block();
    }

    @BeforeEach
    void setUpAdapter() {
        adapter = new WalletTenantConfigR2dbcAdapter(template, template);
        dbClient.sql("DELETE FROM public.tenant_wallet_config").then().block();
    }

    private static TenantWalletConfigDescriptor browserDescriptor() {
        return TenantWalletConfigDescriptor.of(
                "acme", "acme.eudiw.example.com", WalletMode.BROWSER,
                Optional.empty(), false, Collections.emptyList(), 0L);
    }

    @Test
    void save_create_returnsVersionOne() {
        StepVerifier.create(adapter.save(browserDescriptor(), null))
                .assertNext(saved -> {
                    assertThat(saved.getSchemaName()).isEqualTo("acme");
                    assertThat(saved.getWalletMode()).isEqualTo(WalletMode.BROWSER);
                    assertThat(saved.getVersion()).isEqualTo(1L);
                })
                .verifyComplete();
    }

    @Test
    void save_updateWithMatchingExpectedVersion_bumpsVersion() {
        adapter.save(browserDescriptor(), null).block();

        // version is now 1; an update with expectedVersion=1 succeeds and bumps to 2
        StepVerifier.create(adapter.save(browserDescriptor(), 1L))
                .assertNext(saved -> assertThat(saved.getVersion()).isEqualTo(2L))
                .verifyComplete();
    }

    @Test
    void save_updateWithStaleExpectedVersion_failsWithVersionConflict() {
        adapter.save(browserDescriptor(), null).block();
        // bump once via a concurrent-style write so the stored version becomes 2
        adapter.save(browserDescriptor(), null).block();

        // a PUT that still believes version is 1 → optimistic-lock miss
        StepVerifier.create(adapter.save(browserDescriptor(), 1L))
                .expectError(ConfigVersionConflictException.class)
                .verify();

        // and the stored version is unchanged (still 2)
        TenantWalletConfigDescriptor current = adapter.findBySchemaName("acme").block();
        assertThat(current).isNotNull();
        assertThat(current.getVersion()).isEqualTo(2L);
    }
}
