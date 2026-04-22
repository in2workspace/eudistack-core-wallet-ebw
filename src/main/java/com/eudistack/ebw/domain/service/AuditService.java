package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.AuditLogEntry;
import com.eudistack.ebw.domain.repository.AuditLogRepository;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

public class AuditService {

    private final AuditLogRepository auditLogRepository;

    public AuditService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    public Mono<Void> record(String entityType, UUID entityId, String action,
                             UUID actorId, Map<String, Object> metadata) {
        var entry = AuditLogEntry.create(entityType, entityId, action, actorId, metadata);
        return auditLogRepository.save(entry).then();
    }
}
