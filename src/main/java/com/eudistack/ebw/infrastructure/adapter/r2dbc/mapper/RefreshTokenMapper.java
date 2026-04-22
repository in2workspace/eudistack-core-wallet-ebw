package com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper;

import com.eudistack.ebw.domain.model.RefreshToken;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.RefreshTokenEntity;

public final class RefreshTokenMapper {

    private RefreshTokenMapper() {}

    public static RefreshToken toDomain(RefreshTokenEntity entity) {
        return new RefreshToken(entity.getId(), entity.getUserId(), entity.getPasskeyId(),
                entity.getTokenHash(), entity.getExpiresAt(), entity.isRevoked(), entity.getCreatedAt());
    }

    public static RefreshTokenEntity toEntity(RefreshToken domain) {
        return new RefreshTokenEntity(domain.getId(), domain.getUserId(), domain.getPasskeyId(),
                domain.getTokenHash(), domain.getExpiresAt(), domain.isRevoked(), domain.getCreatedAt());
    }
}
