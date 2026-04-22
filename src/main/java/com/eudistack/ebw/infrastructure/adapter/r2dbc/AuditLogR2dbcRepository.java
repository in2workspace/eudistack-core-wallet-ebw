package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.AuditLogEntry;
import com.eudistack.ebw.domain.repository.AuditLogRepository;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper.AuditLogMapper;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.spring.SpringAuditLogRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public class AuditLogR2dbcRepository implements AuditLogRepository {

    private final SpringAuditLogRepository springRepository;

    public AuditLogR2dbcRepository(SpringAuditLogRepository springRepository) {
        this.springRepository = springRepository;
    }

    @Override
    public Mono<AuditLogEntry> save(AuditLogEntry entry) {
        var entity = AuditLogMapper.toEntity(entry);
        entity.markNew();
        return springRepository.save(entity).map(AuditLogMapper::toDomain);
    }
}
