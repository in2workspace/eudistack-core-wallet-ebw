package com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper;

import com.eudistack.ebw.domain.model.AuditLogEntry;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.AuditLogEntity;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;

public final class AuditLogMapper {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private AuditLogMapper() {}

    public static AuditLogEntry toDomain(AuditLogEntity entity) {
        Map<String, Object> metadata = null;
        if (entity.getMetadata() != null) {
            try {
                metadata = OBJECT_MAPPER.readValue(entity.getMetadata(), new TypeReference<>() {});
            } catch (JsonProcessingException e) {
                metadata = Map.of();
            }
        }
        return new AuditLogEntry(entity.getId(), entity.getEntityType(), entity.getEntityId(),
                entity.getAction(), entity.getActorId(), metadata, entity.getCreatedAt());
    }

    public static AuditLogEntity toEntity(AuditLogEntry domain) {
        String metadataJson = null;
        if (domain.getMetadata() != null) {
            try {
                metadataJson = OBJECT_MAPPER.writeValueAsString(domain.getMetadata());
            } catch (JsonProcessingException e) {
                metadataJson = "{}";
            }
        }
        return new AuditLogEntity(domain.getId(), domain.getEntityType(), domain.getEntityId(),
                domain.getAction(), domain.getActorId(), metadataJson, domain.getCreatedAt());
    }
}
