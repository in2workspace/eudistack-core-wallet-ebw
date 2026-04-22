package com.eudistack.ebw.infrastructure.adapter.r2dbc.mapper;

import com.eudistack.ebw.domain.model.EmailVerification;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.EmailVerificationEntity;

public final class VerificationMapper {

    private VerificationMapper() {}

    public static EmailVerification toDomain(EmailVerificationEntity entity) {
        return new EmailVerification(entity.getId(), entity.getUserEmail(), entity.getCodeHash(),
                entity.getAttempts(), entity.getExpiresAt(), entity.isUsed(), entity.getCreatedAt());
    }

    public static EmailVerificationEntity toEntity(EmailVerification domain) {
        return new EmailVerificationEntity(domain.getId(), domain.getUserEmail(), domain.getCodeHash(),
                domain.getAttempts(), domain.getExpiresAt(), domain.isUsed(), domain.getCreatedAt());
    }
}
