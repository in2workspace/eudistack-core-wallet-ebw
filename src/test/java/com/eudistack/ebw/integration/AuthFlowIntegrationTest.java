package com.eudistack.ebw.integration;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.r2dbc.core.DatabaseClient;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AuthFlowIntegrationTest extends IntegrationTestBase {

    @Autowired
    private DatabaseClient databaseClient;

    @BeforeEach
    void setUp() {
        setupEmailCapture();
        capturedOtps.clear();
    }

    @Test
    void fullRegistrationFlow_registerVerifyGetTokens() {
        var email = "test-reg@example.com";

        // Step 1: Register
        webClient.post().uri("/api/v1/auth/register")
                .bodyValue(Map.of("email", email))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.message").isNotEmpty();

        // Step 2: Verify email with captured OTP
        var otp = capturedOtps.get(email);
        assertThat(otp).isNotNull();

        var tokens = webClient.post().uri("/api/v1/auth/verify-email")
                .bodyValue(Map.of("email", email, "code", otp))
                .exchange()
                .expectStatus().isOk()
                .expectBody(Map.class)
                .returnResult().getResponseBody();

        assertThat(tokens).containsKeys("accessToken", "refreshToken", "expiresIn");
        assertThat(tokens.get("accessToken")).asString().isNotBlank();
        assertThat(tokens.get("refreshToken")).asString().isNotBlank();
    }

    @Test
    void tokenRefresh_validToken_returnsNewPair() {
        var email = "test-refresh@example.com";
        var tokens = registerAndVerify(email);

        var newTokens = webClient.post().uri("/api/v1/auth/refresh")
                .bodyValue(Map.of("refreshToken", tokens.get("refreshToken")))
                .exchange()
                .expectStatus().isOk()
                .expectBody(Map.class)
                .returnResult().getResponseBody();

        assertThat(newTokens.get("accessToken")).isNotEqualTo(tokens.get("accessToken"));
        assertThat(newTokens.get("refreshToken")).isNotEqualTo(tokens.get("refreshToken"));
    }

    @Test
    void tokenRefresh_alreadyRotatedToken_returns401_familyCompromise() {
        var email = "test-compromise@example.com";
        var tokens = registerAndVerify(email);
        var oldRefresh = (String) tokens.get("refreshToken");

        // First rotation succeeds
        var newTokens = webClient.post().uri("/api/v1/auth/refresh")
                .bodyValue(Map.of("refreshToken", oldRefresh))
                .exchange()
                .expectStatus().isOk()
                .expectBody(Map.class)
                .returnResult().getResponseBody();

        // Reuse old token (compromise detection)
        webClient.post().uri("/api/v1/auth/refresh")
                .bodyValue(Map.of("refreshToken", oldRefresh))
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.error").isEqualTo("token_compromised");

        // Even the new token should be revoked now (all family revoked)
        webClient.post().uri("/api/v1/auth/refresh")
                .bodyValue(Map.of("refreshToken", newTokens.get("refreshToken")))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void logout_validToken_refreshFails() {
        var email = "test-logout@example.com";
        var tokens = registerAndVerify(email);

        webClient.post().uri("/api/v1/auth/logout")
                .bodyValue(Map.of("refreshToken", tokens.get("refreshToken")))
                .exchange()
                .expectStatus().isNoContent();

        // Refresh with revoked token should fail
        webClient.post().uri("/api/v1/auth/refresh")
                .bodyValue(Map.of("refreshToken", tokens.get("refreshToken")))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void logout_alreadyRevokedToken_stillReturns204() {
        var email = "test-logout-idempotent@example.com";
        var tokens = registerAndVerify(email);

        webClient.post().uri("/api/v1/auth/logout")
                .bodyValue(Map.of("refreshToken", tokens.get("refreshToken")))
                .exchange()
                .expectStatus().isNoContent();

        // Second logout — idempotent
        webClient.post().uri("/api/v1/auth/logout")
                .bodyValue(Map.of("refreshToken", tokens.get("refreshToken")))
                .exchange()
                .expectStatus().isNoContent();
    }

    @Test
    void verifyEmail_wrongCode_returns401() {
        var email = "test-wrong-otp@example.com";
        registerUser(email);

        webClient.post().uri("/api/v1/auth/verify-email")
                .bodyValue(Map.of("email", email, "code", "000000"))
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.error").isEqualTo("invalid_code");
    }

    /**
     * ES-01 (EUD-104): exhausting the OTP attempt budget (5, {@code otp.max-attempts} in
     * application-integration.yaml) MUST fail-closed — 429, no tokens, no passkey — and MUST
     * stay closed even for the correct code afterwards. Expired-code handling is not
     * duplicated here: {@code GlobalExceptionHandler} maps {@code InvalidOtpException} and
     * {@code OtpExpiredException} to the identical 401/invalid_code response (see
     * verifyEmail_wrongCode_returns401), and {@code OtpServiceTest} already covers the
     * expiry branch at the unit level — an IT for it would just re-assert the same HTTP
     * contract this test already exercises for wrong codes.
     */
    @Test
    void verifyEmail_tooManyWrongAttempts_returns429_neverIssuesTokensOrPasskey() {
        var email = "test-otp-exhausted-" + System.nanoTime() + "@example.com";
        registerUser(email);

        for (int i = 0; i < 4; i++) {
            webClient.post().uri("/api/v1/auth/verify-email")
                    .bodyValue(Map.of("email", email, "code", "000000"))
                    .exchange()
                    .expectStatus().isUnauthorized()
                    .expectBody()
                    .jsonPath("$.error").isEqualTo("invalid_code");
        }

        // 5th wrong attempt exhausts the budget.
        webClient.post().uri("/api/v1/auth/verify-email")
                .bodyValue(Map.of("email", email, "code", "000000"))
                .exchange()
                .expectStatus().isEqualTo(429)
                .expectBody()
                .jsonPath("$.error").isEqualTo("too_many_attempts");

        // Fail-closed: even the CORRECT code is now rejected — the window doesn't reopen.
        var otp = capturedOtps.get(email);
        webClient.post().uri("/api/v1/auth/verify-email")
                .bodyValue(Map.of("email", email, "code", otp))
                .exchange()
                .expectStatus().isEqualTo(429);

        // No tokens were ever issued in this flow, so no passkey could have been registered.
        var passkeyCount = databaseClient.sql(
                        "SELECT COUNT(*) AS c FROM user_passkey up "
                        + "JOIN wallet_user wu ON wu.id = up.user_id WHERE wu.email = $1")
                .bind("$1", email)
                .fetch()
                .one()
                .map(row -> (Long) row.get("c"))
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TEST_TENANT))
                .block();
        assertThat(passkeyCount).isZero();
    }

    @Test
    void register_invalidEmail_returns400() {
        webClient.post().uri("/api/v1/auth/register")
                .bodyValue(Map.of("email", "not-an-email"))
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void register_missingEmail_returns400() {
        webClient.post().uri("/api/v1/auth/register")
                .bodyValue(Map.of())
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void refresh_missingToken_returns400() {
        webClient.post().uri("/api/v1/auth/refresh")
                .bodyValue(Map.of("refreshToken", ""))
                .exchange()
                .expectStatus().isBadRequest();
    }

    /**
     * EC-04 (EUD-104) frontier: this scenario re-verifies the SAME email on a device that
     * already has a local passkey — it never calls {@code POST /passkeys} — so it only
     * proves "no duplicate account on re-auth". It MUST NOT be read as covering AC-01
     * (associating a second device/passkey): that outcome is proved separately by
     * {@link SecondDeviceAssociationIT}, which does call {@code POST /passkeys} a second
     * time with a distinct {@code credentialId}. The zero-passkey assertion below is what
     * keeps that boundary honest — if this flow ever started creating a passkey, it would
     * stop being a valid EC-04 fixture.
     */
    @Test
    void reAuthentication_existingUser_issuesNewTokens() {
        var email = "test-reauth-" + System.nanoTime() + "@example.com";
        var firstTokens = registerAndVerify(email);

        // Re-register and verify same email
        var secondTokens = registerAndVerify(email);

        assertThat(secondTokens.get("accessToken")).isNotEqualTo(firstTokens.get("accessToken"));
        assertThat(secondTokens.get("refreshToken")).isNotEqualTo(firstTokens.get("refreshToken"));

        // AC-02: the second alta MUST NOT create a second account for the same email.
        // Unqualified table name — direct DatabaseClient call bypasses the
        // X-Tenant/TenantDomainWebFilter pipeline, so the tenant is supplied explicitly.
        var count = databaseClient.sql("SELECT COUNT(*) AS c FROM wallet_user WHERE email = $1")
                .bind("$1", email)
                .fetch()
                .one()
                .map(row -> (Long) row.get("c"))
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TEST_TENANT))
                .block();
        assertThat(count).isEqualTo(1L);

        // EC-04 frontier: no device/passkey was ever registered in this flow.
        var passkeyCount = databaseClient.sql(
                        "SELECT COUNT(*) AS c FROM user_passkey up "
                        + "JOIN wallet_user wu ON wu.id = up.user_id WHERE wu.email = $1")
                .bind("$1", email)
                .fetch()
                .one()
                .map(row -> (Long) row.get("c"))
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TEST_TENANT))
                .block();
        assertThat(passkeyCount)
                .as("re-auth without a new passkey must not associate any device — that's AC-01's job")
                .isZero();
    }

    // --- Helpers ---

    private void registerUser(String email) {
        webClient.post().uri("/api/v1/auth/register")
                .bodyValue(Map.of("email", email))
                .exchange()
                .expectStatus().isOk();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> registerAndVerify(String email) {
        registerUser(email);
        var otp = capturedOtps.get(email);

        return webClient.post().uri("/api/v1/auth/verify-email")
                .bodyValue(Map.of("email", email, "code", otp))
                .exchange()
                .expectStatus().isOk()
                .expectBody(Map.class)
                .returnResult().getResponseBody();
    }
}
