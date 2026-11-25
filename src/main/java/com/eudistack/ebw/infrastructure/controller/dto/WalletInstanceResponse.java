package com.eudistack.ebw.infrastructure.controller.dto;

import com.eudistack.ebw.domain.model.WalletInstance;

import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;

/** {@code WalletInstance} of EUD-15 {@code annex/openapi.yaml}: {@code current} marks the instance of the session. */
public record WalletInstanceResponse(UUID id, String displayName, String deviceType, Instant createdAt,
                                     Instant lastUsedAt, boolean current) {

    public static WalletInstanceResponse from(WalletInstance instance, UUID currentInstanceId) {
        return new WalletInstanceResponse(instance.id(), instance.displayName(),
                instance.deviceType().name().toLowerCase(Locale.ROOT), instance.createdAt(), instance.lastUsedAt(),
                Objects.equals(instance.id(), currentInstanceId));
    }
}
