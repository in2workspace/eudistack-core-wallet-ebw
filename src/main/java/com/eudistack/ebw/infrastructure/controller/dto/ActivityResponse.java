package com.eudistack.ebw.infrastructure.controller.dto;

import com.eudistack.ebw.domain.model.WalletActivity;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record ActivityResponse(
        UUID id,
        String type,
        @JsonProperty("credential_name") String credentialName,
        String counterparty,
        String details,
        @JsonProperty("shared_attributes") List<String> sharedAttributes,
        @JsonProperty("created_at") Instant createdAt
) {
    public static ActivityResponse from(WalletActivity activity) {
        return new ActivityResponse(
                activity.getId(), activity.getType().name(), activity.getCredentialName(),
                activity.getCounterparty(), activity.getDetails(), activity.getSharedAttributes(),
                activity.getCreatedAt()
        );
    }
}
