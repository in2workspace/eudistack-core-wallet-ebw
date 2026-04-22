package com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper;

import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.WalletUserEntity;

public final class UserMapper {

    private UserMapper() {}

    public static WalletUser toDomain(WalletUserEntity entity) {
        return new WalletUser(entity.getId(), entity.getEmail(), entity.getCreatedAt(), entity.getUpdatedAt());
    }

    public static WalletUserEntity toEntity(WalletUser domain) {
        return new WalletUserEntity(domain.getId(), domain.getEmail(), domain.getCreatedAt(), domain.getUpdatedAt());
    }
}
