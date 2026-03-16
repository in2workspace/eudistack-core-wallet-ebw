package com.eudistack.ebw.domain.repository;

import com.eudistack.ebw.domain.model.AuditLogEntry;
import reactor.core.publisher.Mono;

public interface AuditLogRepository {

    Mono<AuditLogEntry> save(AuditLogEntry entry);
}
