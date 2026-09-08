package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.AuditLogEntry;
import com.eudistack.ebw.domain.repository.AuditLogRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class AuditServiceTest {

    private AuditLogRepository auditLogRepository;
    private AuditService auditService;

    @BeforeEach
    void setUp() {
        auditLogRepository = mock(AuditLogRepository.class);
        auditService = new AuditService(auditLogRepository);
    }

    @Test
    void record_validEvent_savesAuditEntry() {
        // Arrange
        var entityId = UUID.randomUUID();
        var actorId = UUID.randomUUID();
        var metadata = Map.<String, Object>of("detail", "test");
        when(auditLogRepository.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Act
        var result = auditService.record("user", entityId, "USER_CREATED", actorId, metadata);

        // Assert
        StepVerifier.create(result)
                .verifyComplete();

        var captor = ArgumentCaptor.forClass(AuditLogEntry.class);
        verify(auditLogRepository).save(captor.capture());
        assertThat(captor.getValue().getEntityType()).isEqualTo("user");
        assertThat(captor.getValue().getEntityId()).isEqualTo(entityId);
        assertThat(captor.getValue().getAction()).isEqualTo("USER_CREATED");
        assertThat(captor.getValue().getActorId()).isEqualTo(actorId);
    }
}
