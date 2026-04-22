package com.eudistack.ebw.integration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AuthFlowIntegrationTest extends IntegrationTestBase {

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
    void register_disallowedDomain_returns400_andNoOtpSent() {
        var email = "user@evil.com";
        webClient.post().uri("/api/v1/auth/register")
                .bodyValue(Map.of("email", email))
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.violations[0].field").isEqualTo("email")
                .jsonPath("$.violations[0].message").isEqualTo("email domain is not allowed");

        assertThat(capturedOtps).doesNotContainKey(email);
    }

    @Test
    void refresh_missingToken_returns400() {
        webClient.post().uri("/api/v1/auth/refresh")
                .bodyValue(Map.of("refreshToken", ""))
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void reAuthentication_existingUser_issuesNewTokens() {
        var email = "test-reauth@example.com";
        var firstTokens = registerAndVerify(email);

        // Re-register and verify same email
        var secondTokens = registerAndVerify(email);

        assertThat(secondTokens.get("accessToken")).isNotEqualTo(firstTokens.get("accessToken"));
        assertThat(secondTokens.get("refreshToken")).isNotEqualTo(firstTokens.get("refreshToken"));
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
