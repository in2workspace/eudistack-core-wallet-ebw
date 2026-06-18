package com.eudistack.ebw.keymanager.infrastructure.health;

import com.eudistack.ebw.keymanager.application.PrfSaltPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.ReactiveHealthIndicator;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.Mono;

/**
 * Spring Boot Actuator {@link ReactiveHealthIndicator} for the hybrid PRF salt coherence check.
 *
 * <p>Indicator name: {@code salt_coherent} — exposed under
 * {@code /actuator/health/salt_coherent} when the Actuator endpoint is enabled.</p>
 *
 * <p>The check queries {@code hybrid_prf_salt} to detect any {@code (holder_id, credential_id)}
 * pair that has more than one salt row (which the composite PK prevents at the DB level, but
 * which may surface if schema migration is inconsistent or the constraint is dropped).
 * Implementation: {@code SELECT COUNT(*)} grouped by {@code (holder_id, credential_id)} with
 * a {@code HAVING COUNT(*) &gt; 1} filter. If any row is returned, the indicator reports
 * {@code DOWN} with detail {@code salt_coherent=false}; otherwise {@code UP} with
 * {@code salt_coherent=true} (AC-08).</p>
 *
 * <p>The response MUST NOT include any {@code prf_salt} bytes, {@code holder_id} values,
 * or any other PII or cryptographic material (NFR-S-537-01, AC-08).</p>
 *
 * <p>Spec: EUDISTACK-537 AC-08; architecture.md §5.1.</p>
 */
public class HybridHealthContributor implements ReactiveHealthIndicator {

    private static final Logger log = LoggerFactory.getLogger(HybridHealthContributor.class);

    /**
     * Detects any (holder_id, credential_id) pair with more than one salt row.
     * The PK should prevent this; a non-zero count signals a schema integrity issue.
     */
    private static final String COHERENCE_SQL =
            "SELECT COUNT(*) FROM ("
            + "  SELECT holder_id, credential_id "
            + "  FROM hybrid_prf_salt "
            + "  GROUP BY holder_id, credential_id "
            + "  HAVING COUNT(*) > 1"
            + ") violations";

    private final DatabaseClient databaseClient;

    public HybridHealthContributor(DatabaseClient databaseClient) {
        this.databaseClient = databaseClient;
    }

    @Override
    public Mono<Health> health() {
        return databaseClient.sql(COHERENCE_SQL)
                .map((row, metadata) -> row.get(0, Long.class))
                .one()
                .map(violationCount -> {
                    if (violationCount != null && violationCount > 0) {
                        log.warn("keymanager.health.salt_coherent=false violation_count={}", violationCount);
                        return Health.down()
                                .withDetail("salt_coherent", false)
                                .build();
                    }
                    return Health.up()
                            .withDetail("salt_coherent", true)
                            .build();
                })
                .onErrorResume(ex -> {
                    log.error("keymanager.health.salt_coherent check failed exception_class={}",
                            ex.getClass().getName());
                    return Mono.just(Health.down(ex)
                            .withDetail("salt_coherent", false)
                            .build());
                });
    }
}
