package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.TenantConfig;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.TenantConfigEntity;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.spring.SpringTenantConfigRepository;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.UUID;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link TenantConfigR2dbcRepository} — maps the tenant_config row to the domain record.
 */
class TenantConfigR2dbcRepositoryTest {

    @Test
    void findByConfigKey_existingRow_mapsEveryColumn() {
        // Arrange
        var springRepository = mock(SpringTenantConfigRepository.class);
        var id = UUID.randomUUID();
        var created = Instant.parse("2026-01-01T00:00:00Z");
        var updated = Instant.parse("2026-02-01T00:00:00Z");
        when(springRepository.findByConfigKey("ebw.mail_from")).thenReturn(Mono.just(
                new TenantConfigEntity(id, "ebw.mail_from", "wallet@sandbox.example", "Sender", created, updated)));
        var repository = new TenantConfigR2dbcRepository(springRepository);

        // Act
        var result = repository.findByConfigKey("ebw.mail_from");

        // Assert
        StepVerifier.create(result)
                .expectNext(new TenantConfig(id, "ebw.mail_from", "wallet@sandbox.example", "Sender", created, updated))
                .verifyComplete();
    }

    @Test
    void findByConfigKey_missingKey_completesEmpty() {
        // Arrange
        var springRepository = mock(SpringTenantConfigRepository.class);
        when(springRepository.findByConfigKey("missing")).thenReturn(Mono.empty());
        var repository = new TenantConfigR2dbcRepository(springRepository);

        // Act
        var result = repository.findByConfigKey("missing");

        // Assert
        StepVerifier.create(result).verifyComplete();
    }
}
