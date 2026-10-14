package com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper;

import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.UserPasskeyEntity;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;

public final class PasskeyMapper {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final TypeReference<List<String>> STRING_LIST = new TypeReference<>() {};

    private PasskeyMapper() {}

    public static UserPasskey toDomain(UserPasskeyEntity entity) {
        return new UserPasskey(entity.getId(), entity.getUserId(), entity.getCredentialId(),
                entity.getAttestedCredentialData(), entity.getAaguid(), entity.getSignCount(),
                readTransports(entity.getTransports()), entity.isUvInitialized(), entity.isBackupEligible(),
                entity.isBackupState(), entity.getAttestationFormat(), entity.isPrfEnabled(),
                entity.getDisplayName(), entity.getUserAgent(), entity.getCreatedAt(), entity.getLastUsedAt());
    }

    public static UserPasskeyEntity toEntity(UserPasskey domain) {
        var entity = new UserPasskeyEntity();
        entity.setId(domain.getId());
        entity.setUserId(domain.getUserId());
        entity.setCredentialId(domain.getCredentialId());
        entity.setAttestedCredentialData(domain.getAttestedCredentialData());
        entity.setAaguid(domain.getAaguid());
        entity.setSignCount(domain.getSignCount());
        entity.setTransports(writeTransports(domain.getTransports()));
        entity.setUvInitialized(domain.isUvInitialized());
        entity.setBackupEligible(domain.isBackupEligible());
        entity.setBackupState(domain.isBackupState());
        entity.setAttestationFormat(domain.getAttestationFormat());
        entity.setPrfEnabled(domain.isPrfEnabled());
        entity.setDisplayName(domain.getDisplayName());
        entity.setUserAgent(domain.getUserAgent());
        entity.setCreatedAt(domain.getCreatedAt());
        entity.setLastUsedAt(domain.getLastUsedAt());
        return entity;
    }

    private static List<String> readTransports(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        try {
            return OBJECT_MAPPER.readValue(json, STRING_LIST);
        } catch (JsonProcessingException e) {
            return List.of();
        }
    }

    private static String writeTransports(List<String> transports) {
        if (transports == null || transports.isEmpty()) {
            return null;
        }
        try {
            return OBJECT_MAPPER.writeValueAsString(transports);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize passkey transports", e);
        }
    }
}
