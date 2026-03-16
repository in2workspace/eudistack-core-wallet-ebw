package com.eudistack.ebw.domain.model;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public class AuditLogEntry {

    private UUID id;
    private String entityType;
    private UUID entityId;
    private String action;
    private UUID actorId;
    private Map<String, Object> metadata;
    private Instant createdAt;

    public AuditLogEntry(UUID id, String entityType, UUID entityId, String action,
                         UUID actorId, Map<String, Object> metadata, Instant createdAt) {
        this.id = id;
        this.entityType = entityType;
        this.entityId = entityId;
        this.action = action;
        this.actorId = actorId;
        this.metadata = metadata;
        this.createdAt = createdAt;
    }

    public static AuditLogEntry create(String entityType, UUID entityId, String action,
                                       UUID actorId, Map<String, Object> metadata) {
        return new AuditLogEntry(UUID.randomUUID(), entityType, entityId, action, actorId, metadata, Instant.now());
    }

    public UUID getId() { return id; }
    public String getEntityType() { return entityType; }
    public UUID getEntityId() { return entityId; }
    public String getAction() { return action; }
    public UUID getActorId() { return actorId; }
    public Map<String, Object> getMetadata() { return metadata; }
    public Instant getCreatedAt() { return createdAt; }
}
