package com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper;

import com.eudistack.ebw.domain.model.CredentialFormat;
import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.model.WalletCredential;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.WalletCredentialEntity;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;

public final class CredentialMapper {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

    private CredentialMapper() {}

    public static WalletCredential toDomain(WalletCredentialEntity entity) {
        return new WalletCredential(
                entity.getId(),
                entity.getUserId(),
                entity.getCredentialRaw(),
                CredentialFormat.fromValue(entity.getFormat()),
                entity.getCredentialConfigId(),
                entity.getKid(),
                entity.getCredentialType(),
                entity.getVct(),
                entity.getIssuer(),
                entity.getSubject(),
                entity.getIssuanceDate(),
                entity.getExpirationDate(),
                CredentialStatus.valueOf(entity.getStatus()),
                deserializeMetadata(entity.getIssuerMetadata()),
                entity.getCreatedAt(),
                entity.getUpdatedAt()
        );
    }

    public static WalletCredentialEntity toEntity(WalletCredential domain) {
        var entity = new WalletCredentialEntity();
        entity.setId(domain.getId());
        entity.setUserId(domain.getUserId());
        entity.setCredentialRaw(domain.getCredentialRaw());
        entity.setFormat(domain.getFormat().getValue());
        entity.setCredentialConfigId(domain.getCredentialConfigId());
        entity.setKid(domain.getKid());
        entity.setCredentialType(domain.getCredentialType());
        entity.setVct(domain.getVct());
        entity.setIssuer(domain.getIssuer());
        entity.setSubject(domain.getSubject());
        entity.setIssuanceDate(domain.getIssuanceDate());
        entity.setExpirationDate(domain.getExpirationDate());
        entity.setStatus(domain.getStatus().name());
        entity.setIssuerMetadata(serializeMetadata(domain.getIssuerMetadata()));
        entity.setCreatedAt(domain.getCreatedAt());
        entity.setUpdatedAt(domain.getUpdatedAt());
        return entity;
    }

    private static String serializeMetadata(Map<String, Object> metadata) {
        if (metadata == null) return null;
        try {
            return OBJECT_MAPPER.writeValueAsString(metadata);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize issuer_metadata", e);
        }
    }

    private static Map<String, Object> deserializeMetadata(String json) {
        if (json == null || json.isBlank()) return null;
        try {
            return OBJECT_MAPPER.readValue(json, MAP_TYPE);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to deserialize issuer_metadata", e);
        }
    }
}
