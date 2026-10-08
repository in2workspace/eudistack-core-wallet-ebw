package com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper;

import com.eudistack.ebw.domain.model.AuditLogEntry;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.AuditLogEntity;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link AuditLogMapper} — metadata is stored as JSON text and never makes the mapping fail:
 * an unserializable map is written as {@code {}} and an unreadable column is read as an empty map.
 */
class AuditLogMapperTest {

    @Test
    void toEntityThenToDomain_withMetadata_roundTripsEveryField() {
        // Arrange
        var entry = new AuditLogEntry(UUID.randomUUID(), "credential", UUID.randomUUID(), "CREATED",
                UUID.randomUUID(), Map.of("entity_hash", "sha256:abc"), Instant.parse("2026-06-01T12:00:00Z"));

        // Act
        var entity = AuditLogMapper.toEntity(entry);
        var roundTripped = AuditLogMapper.toDomain(entity);

        // Assert
        assertThat(entity.getMetadata()).isEqualTo("{\"entity_hash\":\"sha256:abc\"}");
        assertThat(roundTripped).usingRecursiveComparison().isEqualTo(entry);
    }

    @Test
    void toEntity_nullMetadata_storesNull() {
        // Arrange
        var entry = new AuditLogEntry(UUID.randomUUID(), "user", UUID.randomUUID(), "LOGOUT", null, null, Instant.now());

        // Act
        var entity = AuditLogMapper.toEntity(entry);

        // Assert
        assertThat(entity.getMetadata()).isNull();
        assertThat(AuditLogMapper.toDomain(entity).getMetadata()).isNull();
    }

    @Test
    void toEntity_unserializableMetadata_storesEmptyJsonObject() {
        // Arrange
        var metadata = new HashMap<String, Object>();
        metadata.put("opaque", new Object());
        var entry = new AuditLogEntry(UUID.randomUUID(), "user", UUID.randomUUID(), "X", null, metadata, Instant.now());

        // Act
        var entity = AuditLogMapper.toEntity(entry);

        // Assert
        assertThat(entity.getMetadata()).isEqualTo("{}");
    }

    @Test
    void toDomain_unreadableMetadata_mapsToEmptyMap() {
        // Arrange
        var entity = new AuditLogEntity(UUID.randomUUID(), "user", UUID.randomUUID(), "X", null, "{broken",
                Instant.now());

        // Act
        var entry = AuditLogMapper.toDomain(entity);

        // Assert
        assertThat(entry.getMetadata()).isEmpty();
    }
}
