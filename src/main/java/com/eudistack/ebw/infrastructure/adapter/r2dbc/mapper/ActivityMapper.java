package com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper;

import com.eudistack.ebw.domain.model.ActivityType;
import com.eudistack.ebw.domain.model.WalletActivity;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.WalletActivityEntity;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.r2dbc.postgresql.codec.Json;

import java.util.List;

public final class ActivityMapper {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final TypeReference<List<String>> LIST_TYPE = new TypeReference<>() {};

    private ActivityMapper() {}

    public static WalletActivity toDomain(WalletActivityEntity entity) {
        return new WalletActivity(
                entity.getId(),
                entity.getUserId(),
                ActivityType.valueOf(entity.getType()),
                entity.getCredentialName(),
                entity.getCounterparty(),
                entity.getDetails(),
                deserializeSharedAttributes(entity.getSharedAttributes()),
                entity.getCreatedAt()
        );
    }

    public static WalletActivityEntity toEntity(WalletActivity domain) {
        return new WalletActivityEntity(
                domain.getId(),
                domain.getUserId(),
                domain.getType().name(),
                domain.getCredentialName(),
                domain.getCounterparty(),
                domain.getDetails(),
                serializeSharedAttributes(domain.getSharedAttributes()),
                domain.getCreatedAt()
        );
    }

    private static Json serializeSharedAttributes(List<String> sharedAttributes) {
        if (sharedAttributes == null) return null;
        try {
            return Json.of(OBJECT_MAPPER.writeValueAsString(sharedAttributes));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize shared_attributes", e);
        }
    }

    private static List<String> deserializeSharedAttributes(Json json) {
        if (json == null) return null;
        var asString = json.asString();
        if (asString == null || asString.isBlank()) return null;
        try {
            return OBJECT_MAPPER.readValue(asString, LIST_TYPE);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to deserialize shared_attributes", e);
        }
    }
}
