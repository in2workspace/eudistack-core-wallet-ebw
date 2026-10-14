package com.eudistack.ebw.domain.model;

import java.time.Instant;
import java.util.UUID;

/**
 * Result of opening or renewing a session: the short access token and the raw refresh token
 * (only ever sent in the refresh cookie).
 *
 * @param sessionExpiresAt end of the session's maximum duration, used as the cookie lifetime
 */
public record IssuedSession(
        String accessToken,
        long expiresIn,
        String refreshToken,
        UUID sessionId,
        UUID passkeyId,
        Instant sessionExpiresAt
) {
}
