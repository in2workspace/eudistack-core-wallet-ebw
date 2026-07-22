package com.eudistack.ebw.domain.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Getter
@AllArgsConstructor
public class WalletActivity {

    private UUID id;
    private UUID userId;
    private ActivityType type;
    private String credentialName;
    private String counterparty;
    private String details;
    private List<String> sharedAttributes;
    private Instant createdAt;

    public static WalletActivity create(UUID userId, ActivityType type, String credentialName,
                                         String counterparty, String details, List<String> sharedAttributes) {
        return new WalletActivity(UUID.randomUUID(), userId, type, credentialName, counterparty,
                details, sharedAttributes, Instant.now());
    }
}
