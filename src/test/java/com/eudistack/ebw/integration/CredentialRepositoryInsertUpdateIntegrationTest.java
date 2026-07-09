package com.eudistack.ebw.integration;

import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.model.WalletCredential;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Direct repository-port tests for the {@code insert}/{@code update} split introduced by
 * EUDI-040 review W4. Exercises the {@link WalletCredentialRepository} port (R2DBC adapter)
 * to assert the low-level semantic guarantees that are not observable via the HTTP surface:
 *
 * <ul>
 *   <li>{@code insert} twice with the same id must fail with a duplicate-PK error instead
 *       of silently turning into an UPDATE — this is the whole point of dropping the
 *       previous {@code existsById}-driven {@code save}.</li>
 *   <li>{@code insert} followed by {@code update} on a loaded domain object must succeed
 *       and persist the mutation.</li>
 * </ul>
 *
 * <p>The HTTP surface cannot trigger a duplicate insert (ids are server-generated via
 * {@link WalletCredential#create}), so this must be covered at the port level.
 */
class CredentialRepositoryInsertUpdateIntegrationTest extends IntegrationTestBase {

    @Autowired
    private WalletCredentialRepository credentialRepository;

    @Autowired
    private DatabaseClient databaseClient;

    private String accessToken;
    private String email;

    @BeforeEach
    void setUp() {
        email = "repo-insert-update-" + System.nanoTime() + "@test.com";
        accessToken = getAccessToken(email);
    }

    /**
     * Calling {@code insert} a second time with a credential that already exists in the DB
     * (same primary key) must surface a duplicate-PK error, NOT silently dispatch an UPDATE.
     * This is the core semantic difference from the previous {@code save} implementation,
     * which detected existence via {@code existsById} and switched strategies transparently.
     */
    @Test
    void insert_withDuplicateId_failsWithDataIntegrityViolation() {
        // Store via HTTP to seed a valid row (user FK + all NOT NULL columns populated).
        var stored = storeViaHttp();
        var id = UUID.fromString((String) stored.get("id"));
        var userId = resolveUserId(email);

        // Reload the domain object through the repository port so we have a WalletCredential
        // matching the persisted row.
        var domain = findByIdAndUserId(id, userId);
        assertThat(domain).isNotNull();

        // Second insert with the same id MUST fail rather than silently become an UPDATE.
        StepVerifier.create(withTenantContext(credentialRepository.insert(domain)))
                .expectErrorSatisfies(err -> assertThat(err)
                        .as("duplicate-PK insert must surface a DataIntegrityViolationException")
                        .isInstanceOf(DataIntegrityViolationException.class))
                .verify();
    }

    /**
     * {@code update} on a domain object whose id already exists in the DB must persist the
     * mutation. The UPDATE path is otherwise only exercised via PATCH /status, which has
     * additional workflow guards — this sanity-checks the raw UPDATE dispatch.
     */
    @Test
    void update_existingCredential_persistsMutation() {
        var stored = storeViaHttp();
        var id = UUID.fromString((String) stored.get("id"));
        var userId = resolveUserId(email);

        var loaded = findByIdAndUserId(id, userId);
        assertThat(loaded).isNotNull();
        assertThat(loaded.getStatus()).isEqualTo(CredentialStatus.VALID);

        loaded.setStatus(CredentialStatus.SUSPENDED);
        loaded.setUpdatedAt(Instant.now());

        StepVerifier.create(withTenantContext(credentialRepository.update(loaded)))
                .assertNext(saved -> assertThat(saved.getStatus()).isEqualTo(CredentialStatus.SUSPENDED))
                .verifyComplete();

        var reloaded = findByIdAndUserId(id, userId);
        assertThat(reloaded).isNotNull();
        assertThat(reloaded.getStatus()).isEqualTo(CredentialStatus.SUSPENDED);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> storeViaHttp() {
        var credentialRaw = CredentialCrudIntegrationTest.buildTestJwt(
                "https://issuer-repo-iu.com", "did:example:repo-iu",
                "TestCredential", null);

        return webClient.post().uri("/api/v1/credentials")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of(
                        "credential_raw", credentialRaw,
                        "format", "jwt_vc_json",
                        "credential_configuration_id", "config-repo-iu-" + System.nanoTime(),
                        "kid", "kid-repo-iu-" + System.nanoTime()
                ))
                .exchange()
                .expectStatus().isCreated()
                .expectBody(Map.class)
                .returnResult().getResponseBody();
    }

    private UUID resolveUserId(String email) {
        // Unqualified table name — resolved against the tenant schema via
        // TenantAwareConnectionFactory's search_path (needs the tenant supplied
        // explicitly below since this direct DatabaseClient call bypasses the
        // HTTP request pipeline that would otherwise resolve it from X-Tenant).
        var row = databaseClient.sql("SELECT id FROM wallet_user WHERE email = :email")
                .bind("email", email)
                .fetch()
                .one()
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TEST_TENANT))
                .block();
        assertThat(row).as("wallet_user row must exist for test email").isNotNull();
        return (UUID) row.get("id");
    }

    /**
     * Direct {@link WalletCredentialRepository} calls (unlike the {@code webClient}
     * calls above) bypass {@code TenantDomainWebFilter}, so the tenant must be
     * supplied explicitly for {@code TenantAwareConnectionFactory} to route to the
     * right schema.
     */
    private WalletCredential findByIdAndUserId(UUID id, UUID userId) {
        return withTenantContext(credentialRepository.findByIdAndUserId(id, userId)).block();
    }

    private <T> Mono<T> withTenantContext(Mono<T> mono) {
        return mono.contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TEST_TENANT));
    }
}
