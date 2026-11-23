package com.eudistack.ebw.domain.model;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * A Wallet Instance (EUD-15): one Wallet App used by one account. It has no keys (AD-1): what lets a
 * Wallet App act is that its session is bound to an active instance. A revoked instance never becomes
 * active again.
 *
 * @param registeredPasskeyId passkey of the session that registered it (for "it was not me" and the trace)
 */
public record WalletInstance(UUID id, UUID userId, String displayName, DeviceType deviceType, Status status,
                             Instant createdAt, Instant lastUsedAt, Instant revokedAt, RevokedBy revokedBy,
                             UUID registeredPasskeyId) {

    /** Longest name, after trimming (FR-04, FR-12). */
    public static final int MAX_DISPLAY_NAME_LENGTH = 50;

    public enum DeviceType { MOBILE, TABLET, DESKTOP }

    public enum Status { ACTIVE, REVOKED }

    /** Who revoked it (prd §3.8). */
    public enum RevokedBy { HOLDER, INACTIVITY, DISAVOWAL }

    public WalletInstance {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(userId, "userId");
        Objects.requireNonNull(displayName, "displayName");
        Objects.requireNonNull(deviceType, "deviceType");
        Objects.requireNonNull(status, "status");
    }

    /** A new active instance of the account, registered by the session of {@code passkeyId}. */
    public static WalletInstance register(UUID userId, String displayName, DeviceType deviceType, UUID passkeyId) {
        var now = Instant.now();
        return new WalletInstance(UUID.randomUUID(), userId, normalizeDisplayName(displayName), deviceType,
                Status.ACTIVE, now, now, null, null, Objects.requireNonNull(passkeyId, "passkeyId"));
    }

    public boolean isActive() {
        return status == Status.ACTIVE;
    }

    /**
     * The name trimmed, or {@code null} when it is not valid: empty, longer than
     * {@value #MAX_DISPLAY_NAME_LENGTH} characters, or with control characters (it is shown in emails and
     * screens).
     */
    public static String normalizeDisplayName(String raw) {
        if (raw == null) {
            return null;
        }
        var name = raw.strip();
        if (name.isEmpty() || name.codePointCount(0, name.length()) > MAX_DISPLAY_NAME_LENGTH) {
            return null;
        }
        return name.codePoints().anyMatch(Character::isISOControl) ? null : name;
    }
}
