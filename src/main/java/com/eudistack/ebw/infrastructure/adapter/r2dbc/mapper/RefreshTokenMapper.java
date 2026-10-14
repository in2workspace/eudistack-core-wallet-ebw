package com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper;

import com.eudistack.ebw.domain.model.RefreshToken;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.RefreshTokenEntity;

public final class RefreshTokenMapper {

    private RefreshTokenMapper() {}

    public static RefreshToken toDomain(RefreshTokenEntity entity) {
        return new RefreshToken(entity.getId(), entity.getUserId(), entity.getPasskeyId(), entity.getSessionId(),
                entity.getSessionStartedAt(), entity.getTokenHash(), entity.getExpiresAt(), entity.isRevoked(),
                entity.getCreatedAt());
    }

    public static RefreshTokenEntity toEntity(RefreshToken domain) {
        var entity = new RefreshTokenEntity();
        entity.setId(domain.getId());
        entity.setUserId(domain.getUserId());
        entity.setPasskeyId(domain.getPasskeyId());
        entity.setSessionId(domain.getSessionId());
        entity.setSessionStartedAt(domain.getSessionStartedAt());
        entity.setTokenHash(domain.getTokenHash());
        entity.setExpiresAt(domain.getExpiresAt());
        entity.setRevoked(domain.isRevoked());
        entity.setCreatedAt(domain.getCreatedAt());
        return entity;
    }
}
