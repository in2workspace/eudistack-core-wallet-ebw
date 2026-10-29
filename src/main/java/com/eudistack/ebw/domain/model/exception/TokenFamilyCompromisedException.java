package com.eudistack.ebw.domain.model.exception;

import java.util.UUID;

/** An already rotated refresh token was presented: the whole session has been ended. */
public class TokenFamilyCompromisedException extends RuntimeException {

    private final transient UUID sessionId;
    private final transient UUID userId;

    public TokenFamilyCompromisedException(UUID sessionId, UUID userId) {
        super("Refresh token reuse detected. The session has been ended.");
        this.sessionId = sessionId;
        this.userId = userId;
    }

    public UUID getSessionId() { return sessionId; }
    public UUID getUserId() { return userId; }
}
