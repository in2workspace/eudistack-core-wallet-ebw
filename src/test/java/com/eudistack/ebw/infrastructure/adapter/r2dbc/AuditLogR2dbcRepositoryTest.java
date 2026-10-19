package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.AuditLogEntry;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.AuditLogEntity;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.spring.SpringAuditLogRepository;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link AuditLogR2dbcRepository} — audit rows are append-only, so every save is an insert.
 */
class AuditLogR2dbcRepositoryTest {

    @Test
    void save_entry_insertsAnEntityMarkedNewAndMapsItBack() {
        // Arrange
        var springRepository = mock(SpringAuditLogRepository.class);
        when(springRepository.save(any(AuditLogEntity.class))).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        var repository = new AuditLogR2dbcRepository(springRepository);
        var entry = AuditLogEntry.create("credential", UUID.randomUUID(), "CREATED", UUID.randomUUID(),
                Map.of("format", "dc+sd-jwt"));

        // Act
        var result = repository.save(entry);

        // Assert
        StepVerifier.create(result)
                .assertNext(saved -> assertThat(saved).usingRecursiveComparison().isEqualTo(entry))
                .verifyComplete();
        var saved = ArgumentCaptor.forClass(AuditLogEntity.class);
        verify(springRepository).save(saved.capture());
        assertThat(saved.getValue().isNew()).isTrue();
    }
}
