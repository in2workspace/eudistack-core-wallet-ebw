package com.eudistack.ebw.integration;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.r2dbc.core.DatabaseClient;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * NFR-S-103-01: the full onboarding flow (register -> verify-email -> register passkey)
 * MUST leave a traceable audit_log entry per step: REGISTRATION_INITIATED, USER_AUTHENTICATED,
 * PASSKEY_CREATED, all sharing the same actor_id (the wallet user id).
 */
class OnboardingAuditIT extends IntegrationTestBase {

    @Autowired
    private DatabaseClient databaseClient;

    @BeforeEach
    void setUp() {
        setupEmailCapture();
        capturedOtps.clear();
    }

    @Test
    void fullOnboarding_emitsRegistrationInitiated_userAuthenticated_andPasskeyCreated() {
        var email = "onboarding-audit-" + System.nanoTime() + "@example.com";

        webClient.post().uri("/api/v1/auth/register")
                .bodyValue(Map.of("email", email))
                .exchange()
                .expectStatus().isOk();

        var otp = capturedOtps.get(email);
        assertThat(otp).isNotNull();

        @SuppressWarnings("unchecked")
        var tokens = webClient.post().uri("/api/v1/auth/verify-email")
                .bodyValue(Map.of("email", email, "code", otp))
                .exchange()
                .expectStatus().isOk()
                .expectBody(Map.class)
                .returnResult().getResponseBody();
        var accessToken = (String) tokens.get("accessToken");

        webClient.post().uri("/api/v1/auth/passkeys")
                .headers(h -> h.setBearerAuth(accessToken))
                .bodyValue(Map.of(
                        "credentialId", "cred-audit-" + System.nanoTime(),
                        "displayName", "Test Device"))
                .exchange()
                .expectStatus().isCreated();

        // Unqualified table names — resolved against the tenant schema via
        // TenantAwareConnectionFactory's search_path, which requires the tenant to be
        // present in the Reactor Context (the HTTP calls above get it from the
        // X-Tenant header/TenantDomainWebFilter; these direct DatabaseClient calls
        // bypass that pipeline, so it's supplied explicitly below).
        var userId = databaseClient.sql("SELECT id FROM wallet_user WHERE email = $1")
                .bind("$1", email)
                .fetch()
                .one()
                .map(row -> row.get("id"))
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TEST_TENANT))
                .block();
        assertThat(userId).isNotNull();

        List<Map<String, Object>> rows = databaseClient.sql(
                        "SELECT action FROM audit_log WHERE actor_id = $1::uuid ORDER BY created_at ASC")
                .bind("$1", userId.toString())
                .fetch()
                .all()
                .collectList()
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TEST_TENANT))
                .block();

        assertThat(rows).extracting(row -> row.get("action"))
                .containsExactlyInAnyOrder("REGISTRATION_INITIATED", "USER_AUTHENTICATED", "PASSKEY_CREATED");
    }
}
