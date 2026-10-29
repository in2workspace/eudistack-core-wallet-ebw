package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.keymanager.application.SessionPasskeyCredentialPort;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.Mono;

import java.util.UUID;

/** {@link SessionPasskeyCredentialPort} over {@code wallet_credential} (tenant schema via {@code search_path}). */
public class SessionPasskeyCredentialR2dbcAdapter implements SessionPasskeyCredentialPort {

    private static final String EXISTS_SQL = """
            SELECT EXISTS (
                SELECT 1 FROM wallet_credential
                 WHERE user_id = :userId AND holder_key_id = :credentialId AND passkey_id = :passkeyId
            ) AS obtained
            """;

    private final DatabaseClient databaseClient;

    public SessionPasskeyCredentialR2dbcAdapter(DatabaseClient databaseClient) {
        this.databaseClient = databaseClient;
    }

    @Override
    public Mono<Boolean> isObtainedWithPasskey(String holderId, String credentialId, String passkeyId) {
        if (holderId == null || credentialId == null || passkeyId == null) {
            return Mono.just(false);
        }
        return databaseClient.sql(EXISTS_SQL)
                .bind("userId", UUID.fromString(holderId))
                .bind("credentialId", credentialId)
                .bind("passkeyId", UUID.fromString(passkeyId))
                .map((row, metadata) -> Boolean.TRUE.equals(row.get("obtained", Boolean.class)))
                .one()
                .defaultIfEmpty(false);
    }
}
