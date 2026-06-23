package com.eudistack.ebw.keymanager.infrastructure.health;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.ReactiveHealthIndicator;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.Mono;

/**
 * Spring Boot Actuator {@link ReactiveHealthIndicator} for the hybrid PRF salt table
 * reachability check.
 *
 * <p>Indicator name: {@code salt_coherent} — exposed under
 * {@code /actuator/health/salt_coherent} when the Actuator endpoint is enabled.</p>
 *
 * <p>The check issues a lightweight {@code SELECT 1 FROM hybrid_prf_salt LIMIT 1} probe to
 * confirm the table is readable in the tenant schema. {@code salt_coherent=true} (UP) means
 * the table is accessible; {@code salt_coherent=false} (DOWN) signals a genuine SQL error
 * accessing the table (e.g. missing migration, revoked privileges).</p>
 *
 * <p>When invoked without a tenant context (e.g. from the Actuator outside an HTTP request),
 * the indicator returns UP with a note rather than triggering a misleading DOWN caused by the
 * {@code search_path} falling back to {@code public} where the table does not exist.</p>
 *
 * <p>Full per-tenant coherence (detecting credentials without a salt row) is delivered by
 * EUDISTACK-541 (US-09) per architecture §5.4.</p>
 *
 * <p>The response MUST NOT include any {@code prf_salt} bytes, {@code holder_id} values,
 * or any other PII or cryptographic material (NFR-S-537-01, AC-08).</p>
 *
 * <p>Spec: EUDISTACK-537 AC-08; architecture.md §5.1.</p>
 */
public class HybridHealthContributor implements ReactiveHealthIndicator {

    private static final Logger log = LoggerFactory.getLogger(HybridHealthContributor.class);

    /**
     * Simple reachability probe: succeeds when the table exists and is readable in the
     * current tenant schema. Returns zero rows on an empty table; that is still a success.
     */
    private static final String PROBE_SQL = "SELECT 1 FROM hybrid_prf_salt LIMIT 1";

    private final DatabaseClient databaseClient;

    public HybridHealthContributor(DatabaseClient databaseClient) {
        this.databaseClient = databaseClient;
    }

    @Override
    public Mono<Health> health() {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, null);
            if (tenant == null || tenant.isBlank()) {
                // No tenant context: the DB query would hit search_path=public where the table
                // does not exist, yielding a misleading DOWN. Return UP with an explanatory note.
                return Mono.just(Health.up()
                        .withDetail("salt_coherent", true)
                        .withDetail("note", "no tenant context — full coherence delegated to US-09")
                        .build());
            }
            return runProbe();
        });
    }

    private Mono<Health> runProbe() {
        return databaseClient.sql(PROBE_SQL)
                .fetch()
                .all()
                .then(Mono.just(Health.up()
                        .withDetail("salt_coherent", true)
                        .build()))
                .onErrorResume(ex -> {
                    log.error("keymanager.health.salt_coherent check failed exception_class={}",
                            ex.getClass().getName());
                    return Mono.just(Health.down(ex)
                            .withDetail("salt_coherent", false)
                            .build());
                });
    }
}
