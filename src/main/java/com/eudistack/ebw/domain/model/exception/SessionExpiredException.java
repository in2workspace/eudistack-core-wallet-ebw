package com.eudistack.ebw.domain.model.exception;

import java.util.Locale;
import java.util.UUID;

/** The session reached its inactivity period or its maximum duration. */
public class SessionExpiredException extends RuntimeException {

    public enum Reason {
        IDLE_TIMEOUT, MAX_DURATION;

        /** Value of the {@code reason} of the {@code SESSION_EXPIRED} audit event. */
        public String code() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    private final transient UUID sessionId;
    private final transient UUID userId;
    private final Reason reason;

    public SessionExpiredException(UUID sessionId, UUID userId, Reason reason) {
        super("Session expired: " + reason);
        this.sessionId = sessionId;
        this.userId = userId;
        this.reason = reason;
    }

    public UUID getSessionId() { return sessionId; }
    public UUID getUserId() { return userId; }
    public Reason getReason() { return reason; }
}
