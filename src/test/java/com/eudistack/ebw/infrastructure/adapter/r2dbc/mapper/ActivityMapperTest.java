package com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper;

import com.eudistack.ebw.domain.model.ActivityType;
import com.eudistack.ebw.domain.model.WalletActivity;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.WalletActivityEntity;
import io.r2dbc.postgresql.codec.Json;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link ActivityMapper} — column mapping and the JSONB {@code shared_attributes} codec.
 */
class ActivityMapperTest {

    @Test
    void toEntityThenToDomain_withSharedAttributes_roundTripsEveryField() {
        // Arrange
        var activity = new WalletActivity(UUID.randomUUID(), UUID.randomUUID(), ActivityType.PRESENTED, "LEAR",
                "https://verifier", "details", List.of("given_name", "family_name"),
                Instant.parse("2026-06-01T12:00:00Z"));

        // Act
        var entity = ActivityMapper.toEntity(activity);
        var roundTripped = ActivityMapper.toDomain(entity);

        // Assert
        assertThat(entity.getType()).isEqualTo("PRESENTED");
        assertThat(entity.getSharedAttributes().asString()).isEqualTo("[\"given_name\",\"family_name\"]");
        assertThat(roundTripped).usingRecursiveComparison().isEqualTo(activity);
    }

    @Test
    void toEntityThenToDomain_withoutSharedAttributes_keepsThemNull() {
        // Arrange
        var activity = WalletActivity.create(UUID.randomUUID(), ActivityType.ISSUED, "LEAR", "issuer", null, null);

        // Act
        var entity = ActivityMapper.toEntity(activity);

        // Assert
        assertThat(entity.getSharedAttributes()).isNull();
        assertThat(ActivityMapper.toDomain(entity).getSharedAttributes()).isNull();
    }

    @Test
    void toDomain_blankSharedAttributes_mapsToNull() {
        // Arrange
        var entity = entity(Json.of(""));

        // Act
        var activity = ActivityMapper.toDomain(entity);

        // Assert
        assertThat(activity.getSharedAttributes()).isNull();
    }

    @Test
    void toDomain_corruptSharedAttributes_failsWithIllegalState() {
        // Arrange
        var entity = entity(Json.of("{\"not\":\"a list\"}"));

        // Act + Assert
        assertThatThrownBy(() -> ActivityMapper.toDomain(entity))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Failed to deserialize shared_attributes");
    }

    private static WalletActivityEntity entity(Json sharedAttributes) {
        return new WalletActivityEntity(UUID.randomUUID(), UUID.randomUUID(), "DELETED", "LEAR", "cp", null,
                sharedAttributes, Instant.now());
    }
}
