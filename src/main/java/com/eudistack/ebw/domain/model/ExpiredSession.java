package com.eudistack.ebw.domain.model;

import com.eudistack.ebw.domain.model.exception.SessionExpiredException.Reason;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * A session that lapsed without being renewed or ended, closed by the housekeeping pass.
 * {@code lastExpiresAt} is the expiry of its last token.
 */
public record ExpiredSession(UUID sessionId, UUID userId, Instant sessionStartedAt, Instant lastExpiresAt) {

    /**
     * The token expiry is capped at the session's maximum duration, so a last token that expires
     * at (or past) that limit means the session reached it; otherwise it was left inactive.
     */
    public Reason reason(Duration maxDuration) {
        return lastExpiresAt.isBefore(sessionStartedAt.plus(maxDuration)) ? Reason.IDLE_TIMEOUT : Reason.MAX_DURATION;
    }
}
