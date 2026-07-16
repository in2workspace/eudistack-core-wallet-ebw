package com.eudistack.ebw.integration;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.r2dbc.core.DatabaseClient;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AC-01 / AC-05: verify -> register passkey with an edited displayName MUST create the
 * account (if it did not exist yet) and persist the passkey with the exact edited name.
 */
class RegisterPasskeyFlowIT extends IntegrationTestBase {

    @Autowired
    private DatabaseClient databaseClient;

    @BeforeEach
    void setUp() {
        setupEmailCapture();
        capturedOtps.clear();
    }

    @Test
    void verifyThenRegisterPasskey_withEditedDisplayName_createsAccountAndPasskey() {
        var email = "passkey-flow-" + System.nanoTime() + "@example.com";
        var editedDisplayName = "My Edited Laptop Name";
        var credentialId = "cred-flow-" + System.nanoTime();

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

        @SuppressWarnings("unchecked")
        var passkey = webClient.post().uri("/api/v1/auth/passkeys")
                .headers(h -> h.setBearerAuth(accessToken))
                .bodyValue(Map.of(
                        "credentialId", credentialId,
                        "displayName", editedDisplayName))
                .exchange()
                .expectStatus().isCreated()
                .expectBody(Map.class)
                .returnResult().getResponseBody();

        assertThat(passkey.get("displayName")).isEqualTo(editedDisplayName);
        assertThat(passkey.get("credentialId")).isEqualTo(credentialId);

        // AC-01: the account was created for this (previously unknown) email.
        // Unqualified table names — resolved via search_path; direct DatabaseClient
        // calls bypass the X-Tenant/TenantDomainWebFilter pipeline, so the tenant is
        // supplied explicitly via contextWrite (see OnboardingAuditIT for the same pattern).
        var userRow = databaseClient.sql("SELECT id FROM wallet_user WHERE email = $1")
                .bind("$1", email)
                .fetch()
                .one()
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TEST_TENANT))
                .block();
        assertThat(userRow).isNotNull();

        // AC-05: the passkey is persisted with the edited display name, linked to that account
        var passkeyRow = databaseClient.sql(
                        "SELECT display_name, user_id FROM user_passkey WHERE credential_id = $1")
                .bind("$1", credentialId)
                .fetch()
                .one()
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TEST_TENANT))
                .block();
        assertThat(passkeyRow.get("display_name")).isEqualTo(editedDisplayName);
        assertThat(passkeyRow.get("user_id").toString()).isEqualTo(userRow.get("id").toString());
    }
}
