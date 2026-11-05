package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.keymanager.application.PrfSaltPort;
import com.eudistack.ebw.keymanager.domain.model.PrfSalt;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.r2dbc.postgresql.codec.Json;
import io.r2dbc.spi.R2dbcException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

/**
 * R2DBC adapter for the {@code passkey_prf_salt} table, implementing {@link PrfSaltPort}.
 *
 * <p>Uses raw {@link DatabaseClient} SQL because the table has a composite primary key
 * ({@code holder_id, credential_id}), which Spring Data R2DBC does not support natively.
 * Tenant isolation is via PostgreSQL {@code search_path} set by
 * {@code TenantAwareConnectionFactoryDecorator}.</p>
 *
 * <p>Duplicate-key on INSERT is a benign signal in the get-or-create scenario: when two concurrent
 * requests race, the loser swallows the {@link DataIntegrityViolationException} and the caller reads
 * the winner's row.</p>
 */
public class PrfSaltRepository implements PrfSaltPort {

    private static final String SELECT_SQL =
            "SELECT prf_salt, passkey_id, public_jwk FROM passkey_prf_salt "
            + "WHERE holder_id = :holderId AND credential_id = :credentialId";

    private static final String INSERT_SQL =
            "INSERT INTO passkey_prf_salt (holder_id, credential_id, passkey_id, prf_salt) "
            + "VALUES (:holderId, :credentialId, :passkeyId, :prfSalt)";

    private static final String SET_PUBLIC_JWK_SQL =
            "UPDATE passkey_prf_salt SET public_jwk = :publicJwk "
            + "WHERE holder_id = :holderId AND credential_id = :credentialId "
            + "AND passkey_id = :passkeyId AND public_jwk IS NULL";

    private static final String DELETE_SQL =
            "DELETE FROM passkey_prf_salt WHERE holder_id = :holderId AND credential_id = :credentialId";

    private static final TypeReference<Map<String, Object>> JWK_TYPE = new TypeReference<>() { };

    private final DatabaseClient databaseClient;
    private final ObjectMapper objectMapper;

    public PrfSaltRepository(DatabaseClient databaseClient, ObjectMapper objectMapper) {
        this.databaseClient = databaseClient;
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<PrfSalt> findBy(String holderId, String credentialId) {
        return databaseClient.sql(SELECT_SQL)
                .bind("holderId", UUID.fromString(holderId))
                .bind("credentialId", credentialId)
                .map((row, metadata) -> {
                    UUID passkeyId = row.get("passkey_id", UUID.class);
                    Json publicJwk = row.get("public_jwk", Json.class);
                    return new PrfSalt(credentialId, row.get("prf_salt", byte[].class),
                            passkeyId != null ? passkeyId.toString() : null,
                            publicJwk != null ? parseJwk(publicJwk) : null);
                })
                .one();
    }

    /**
     * A {@link DataIntegrityViolationException} caused by a duplicate composite key (SQLSTATE 23505) is
     * swallowed. Any other integrity violation (FK 23503, CHECK 23514) propagates as-is so the caller
     * is not misled.
     */
    @Override
    public Mono<Boolean> insert(String holderId, String credentialId, String passkeyId, byte[] prfSalt) {
        return databaseClient.sql(INSERT_SQL)
                .bind("holderId", UUID.fromString(holderId))
                .bind("credentialId", credentialId)
                .bind("passkeyId", UUID.fromString(passkeyId))
                .bind("prfSalt", prfSalt)
                .fetch()
                .rowsUpdated()
                .map(rows -> rows > 0)
                .onErrorResume(
                        ex -> ex instanceof DataIntegrityViolationException && isUniqueViolation(ex),
                        ex -> Mono.just(false));
    }

    @Override
    public Mono<Boolean> setPublicJwk(String holderId, String credentialId, String passkeyId,
                                      Map<String, Object> publicJwk) {
        return databaseClient.sql(SET_PUBLIC_JWK_SQL)
                .bind("publicJwk", serializeJwk(publicJwk))
                .bind("holderId", UUID.fromString(holderId))
                .bind("credentialId", credentialId)
                .bind("passkeyId", UUID.fromString(passkeyId))
                .fetch()
                .rowsUpdated()
                .map(rows -> rows > 0);
    }

    @Override
    public Mono<Boolean> delete(String holderId, String credentialId) {
        return databaseClient.sql(DELETE_SQL)
                .bind("holderId", UUID.fromString(holderId))
                .bind("credentialId", credentialId)
                .fetch()
                .rowsUpdated()
                .map(rows -> rows > 0);
    }

    /**
     * Returns {@code true} only when the root cause is an R2DBC unique-constraint violation
     * (SQLSTATE {@code 23505}). Traverses the cause chain because Spring's
     * {@link DataIntegrityViolationException} wraps the underlying {@link R2dbcException}.
     */
    private boolean isUniqueViolation(Throwable ex) {
        Throwable cause = ex;
        while (cause != null) {
            if (cause instanceof R2dbcException r2dbc && "23505".equals(r2dbc.getSqlState())) {
                return true;
            }
            cause = cause.getCause();
        }
        return false;
    }

    private Map<String, Object> parseJwk(Json json) {
        try {
            return objectMapper.readValue(json.asString(), JWK_TYPE);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to deserialize public JWK from database", e);
        }
    }

    private Json serializeJwk(Map<String, Object> jwk) {
        try {
            return Json.of(objectMapper.writeValueAsString(jwk));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize public JWK for database", e);
        }
    }
}
