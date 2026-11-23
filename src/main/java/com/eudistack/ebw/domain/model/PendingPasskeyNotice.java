package com.eudistack.ebw.domain.model;

import java.time.Instant;
import java.util.UUID;

/**
 * A new-passkey email still owed for a session that ended without binding or registering a Wallet Instance
 * (EUD-8 AD-11). {@code passkeyAddedAt} is the registration time of the session's passkey, the one the email
 * shows.
 */
public record PendingPasskeyNotice(UUID sessionId, UUID userId, UUID passkeyId, Instant passkeyAddedAt) {
}
