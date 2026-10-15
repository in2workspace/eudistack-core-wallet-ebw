package com.eudistack.ebw.support;

import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.WalletUser;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

/** Test fixtures for passkeys and accounts (domain objects and SQL rows). */
public final class TestPasskeys {

    private static final SecureRandom RANDOM = new SecureRandom();

    private TestPasskeys() {}

    /** A passkey with a dummy credential record (not verifiable), for tests that do not run WebAuthn. */
    public static UserPasskey create(UUID userId, String credentialId, String displayName, String userAgent) {
        var now = Instant.now();
        return new UserPasskey(UUID.randomUUID(), userId, credentialId, new byte[] {1, 2, 3}, null, 0,
                List.of("internal"), true, true, true, "none", true, displayName, userAgent, now, now);
    }

    public static WalletUser user(String email) {
        return WalletUser.create(email, randomBytes(32));
    }

    public static byte[] randomBytes(int length) {
        var bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    /** SQL for a {@code wallet_user} row with a random user handle. */
    public static void insertUser(Connection conn, String schema, UUID userId, String email) throws SQLException {
        conn.createStatement().execute("INSERT INTO " + schema + ".wallet_user (id, email, webauthn_user_handle) "
                + "VALUES ('" + userId + "', '" + email + "', decode('" + HexFormat.of().formatHex(randomBytes(32))
                + "', 'hex')) ON CONFLICT (id) DO NOTHING");
    }

    /** SQL for a {@code user_passkey} row with a dummy credential record. */
    public static void insertPasskey(Connection conn, String schema, UUID id, UUID userId, String credentialId,
                                     String displayName, Instant createdAt, Instant lastUsedAt) throws SQLException {
        String lastUsed = lastUsedAt == null ? "NULL" : "'" + lastUsedAt + "'";
        conn.createStatement().execute("INSERT INTO " + schema + ".user_passkey "
                + "(id, user_id, credential_id, display_name, user_agent, created_at, last_used_at, "
                + "attested_credential_data, sign_count, uv_initialized, backup_eligible, backup_state, prf_enabled) "
                + "VALUES ('" + id + "', '" + userId + "', '" + credentialId + "', '" + displayName
                + "', 'test-agent', '" + createdAt + "', " + lastUsed
                + ", decode('010203', 'hex'), 0, true, true, true, true)");
    }

    /** SQL for an active {@code refresh_token} row (one token = one session). */
    public static void insertSession(Connection conn, String schema, UUID userId, UUID passkeyId,
                                     String tokenHash) throws SQLException {
        conn.createStatement().execute("INSERT INTO " + schema + ".refresh_token "
                + "(id, user_id, passkey_id, session_id, session_started_at, token_hash, expires_at, revoked) "
                + "VALUES ('" + UUID.randomUUID() + "', '" + userId + "', '" + passkeyId + "', '" + UUID.randomUUID()
                + "', NOW(), '" + tokenHash + "', NOW() + INTERVAL '15 minutes', false)");
    }
}
