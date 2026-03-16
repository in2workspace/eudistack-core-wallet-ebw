package com.eudistack.ebw.infrastructure.controller.dto;

import com.eudistack.ebw.application.workflow.ListPasskeysWorkflow.PasskeyWithSessions;
import com.eudistack.ebw.domain.model.UserPasskey;

import java.time.Instant;
import java.util.UUID;

public record PasskeyResponse(
        UUID id,
        String credentialId,
        String displayName,
        String userAgent,
        Instant createdAt,
        Instant lastUsedAt,
        long activeSessions
) {
    public static PasskeyResponse from(PasskeyWithSessions pws) {
        UserPasskey p = pws.passkey();
        return new PasskeyResponse(p.getId(), p.getCredentialId(), p.getDisplayName(),
                p.getUserAgent(), p.getCreatedAt(), p.getLastUsedAt(), pws.activeSessions());
    }

    public static PasskeyResponse from(UserPasskey p) {
        return new PasskeyResponse(p.getId(), p.getCredentialId(), p.getDisplayName(),
                p.getUserAgent(), p.getCreatedAt(), p.getLastUsedAt(), 0);
    }
}
