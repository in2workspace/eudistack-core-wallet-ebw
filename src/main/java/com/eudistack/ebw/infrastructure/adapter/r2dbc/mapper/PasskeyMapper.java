package com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper;

import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.UserPasskeyEntity;

public final class PasskeyMapper {

    private PasskeyMapper() {}

    public static UserPasskey toDomain(UserPasskeyEntity entity) {
        return new UserPasskey(entity.getId(), entity.getUserId(), entity.getCredentialId(),
                entity.getDisplayName(), entity.getUserAgent(), entity.getCreatedAt(), entity.getLastUsedAt());
    }

    public static UserPasskeyEntity toEntity(UserPasskey domain) {
        return new UserPasskeyEntity(domain.getId(), domain.getUserId(), domain.getCredentialId(),
                domain.getDisplayName(), domain.getUserAgent(), domain.getCreatedAt(), domain.getLastUsedAt());
    }
}
