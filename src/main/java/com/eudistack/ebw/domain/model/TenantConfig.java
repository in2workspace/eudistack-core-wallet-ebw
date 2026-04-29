package com.eudistack.ebw.domain.model;

import java.time.Instant;
import java.util.UUID;

public record TenantConfig(
        UUID id,
        String configKey,
        String configValue,
        String description,
        Instant createdAt,
        Instant updatedAt
) {
}
