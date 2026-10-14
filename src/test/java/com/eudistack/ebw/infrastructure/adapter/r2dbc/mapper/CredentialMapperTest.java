package com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper;

import com.eudistack.ebw.domain.model.CredentialFormat;
import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.model.WalletCredential;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.WalletCredentialEntity;
import io.r2dbc.postgresql.codec.Json;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link CredentialMapper} — column mapping and the JSONB {@code issuer_metadata} codec.
 */
class CredentialMapperTest {

    @Test
    void toEntityThenToDomain_fullCredential_roundTripsEveryField() {
        // Arrange
        var now = Instant.parse("2026-06-01T12:00:00Z");
        var metadata = Map.<String, Object>of("credential_issuer", "https://issuer", "display", List.of("x"));
        var credential = new WalletCredential(UUID.randomUUID(), UUID.randomUUID(), "raw", CredentialFormat.JWT_VC_JSON,
                "cfg-1", "kid-1", "LEARCredentialEmployee", "urn:vct", "https://issuer", "did:sub",
                now, now.plusSeconds(3600), CredentialStatus.SUSPENDED, metadata, "hk-1", now, now.plusSeconds(1));

        // Act
        var entity = CredentialMapper.toEntity(credential);
        var roundTripped = CredentialMapper.toDomain(entity);

        // Assert
        assertThat(entity.getFormat()).isEqualTo("jwt_vc_json");
        assertThat(entity.getStatus()).isEqualTo("SUSPENDED");
        assertThat(entity.isNew()).isFalse();
        assertThat(roundTripped).usingRecursiveComparison().isEqualTo(credential);
    }

    @Test
    void toEntity_nullMetadata_storesNullJson() {
        // Arrange
        var credential = new WalletCredential(UUID.randomUUID(), UUID.randomUUID(), "raw", CredentialFormat.DC_SD_JWT,
                "cfg", null, "Type", null, "iss", null, Instant.now(), null, CredentialStatus.VALID,
                null, null, Instant.now(), Instant.now());

        // Act
        var entity = CredentialMapper.toEntity(credential);

        // Assert
        assertThat(entity.getIssuerMetadata()).isNull();
        assertThat(CredentialMapper.toDomain(entity).getIssuerMetadata()).isNull();
    }

    @Test
    void toDomain_blankMetadataJson_mapsToNull() {
        // Arrange
        var entity = entity(Json.of("  "));

        // Act
        var credential = CredentialMapper.toDomain(entity);

        // Assert
        assertThat(credential.getIssuerMetadata()).isNull();
    }

    @Test
    void toDomain_corruptMetadataJson_failsWithIllegalState() {
        // Arrange
        var entity = entity(Json.of("{not json"));

        // Act + Assert
        assertThatThrownBy(() -> CredentialMapper.toDomain(entity))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Failed to deserialize issuer_metadata");
    }

    @Test
    void toEntity_unserializableMetadata_failsWithIllegalState() {
        // Arrange
        var metadata = new HashMap<String, Object>();
        metadata.put("opaque", new Object());
        var credential = new WalletCredential(UUID.randomUUID(), UUID.randomUUID(), "raw", CredentialFormat.DC_SD_JWT,
                "cfg", null, "Type", null, "iss", null, Instant.now(), null, CredentialStatus.VALID,
                metadata, null, Instant.now(), Instant.now());

        // Act + Assert
        assertThatThrownBy(() -> CredentialMapper.toEntity(credential))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Failed to serialize issuer_metadata");
    }

    private static WalletCredentialEntity entity(Json metadata) {
        var entity = new WalletCredentialEntity();
        entity.setId(UUID.randomUUID());
        entity.setUserId(UUID.randomUUID());
        entity.setFormat("dc+sd-jwt");
        entity.setStatus("VALID");
        entity.setIssuerMetadata(metadata);
        return entity;
    }
}
