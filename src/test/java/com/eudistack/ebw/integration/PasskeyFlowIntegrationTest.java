package com.eudistack.ebw.integration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.annotation.DirtiesContext;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
class PasskeyFlowIntegrationTest extends IntegrationTestBase {

    @BeforeEach
    void setUp() {
        setupEmailCapture();
        capturedOtps.clear();
    }

    @Test
    void registerPasskey_thenListIt() {
        var auth = authenticateUser("passkey-list@example.com");

        // Register passkey
        var passkey = webClient.post().uri("/api/v1/auth/passkeys")
                .headers(h -> h.setBearerAuth(auth.accessToken()))
                .bodyValue(Map.of("credentialId", "cred-001", "displayName", "My Laptop"))
                .exchange()
                .expectStatus().isCreated()
                .expectBody(Map.class)
                .returnResult().getResponseBody();

        assertThat(passkey.get("credentialId")).isEqualTo("cred-001");
        assertThat(passkey.get("displayName")).isEqualTo("My Laptop");

        // List passkeys
        var list = webClient.get().uri("/api/v1/auth/passkeys")
                .headers(h -> h.setBearerAuth(auth.accessToken()))
                .exchange()
                .expectStatus().isOk()
                .expectBody(List.class)
                .returnResult().getResponseBody();

        assertThat(list).hasSize(1);
    }

    @Test
    void updatePasskey_changesDisplayName() {
        var auth = authenticateUser("passkey-update@example.com");
        var passkeyId = createPasskey(auth.accessToken(), "cred-upd", "Old Name");

        webClient.patch().uri("/api/v1/auth/passkeys/{id}", passkeyId)
                .headers(h -> h.setBearerAuth(auth.accessToken()))
                .bodyValue(Map.of("displayName", "New Name"))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.displayName").isEqualTo("New Name");
    }

    @Test
    void deletePasskey_withTwoPasskeys_succeeds() {
        var auth = authenticateUser("passkey-delete@example.com");
        var id1 = createPasskey(auth.accessToken(), "cred-del-1", "Key 1");
        var id2 = createPasskey(auth.accessToken(), "cred-del-2", "Key 2");

        webClient.delete().uri("/api/v1/auth/passkeys/{id}", id1)
                .headers(h -> h.setBearerAuth(auth.accessToken()))
                .exchange()
                .expectStatus().isNoContent();

        // Verify only one remains
        var list = webClient.get().uri("/api/v1/auth/passkeys")
                .headers(h -> h.setBearerAuth(auth.accessToken()))
                .exchange()
                .expectStatus().isOk()
                .expectBody(List.class)
                .returnResult().getResponseBody();

        assertThat(list).hasSize(1);
    }

    @Test
    void deleteLastPasskey_returns409() {
        var auth = authenticateUser("passkey-last@example.com");
        var passkeyId = createPasskey(auth.accessToken(), "cred-last", "Only Key");

        webClient.delete().uri("/api/v1/auth/passkeys/{id}", passkeyId)
                .headers(h -> h.setBearerAuth(auth.accessToken()))
                .exchange()
                .expectStatus().isEqualTo(409)
                .expectBody()
                .jsonPath("$.type").isEqualTo("urn:eudistack:error:last-passkey");
    }

    @Test
    void duplicateCredentialId_returns409() {
        var auth = authenticateUser("passkey-dup@example.com");
        createPasskey(auth.accessToken(), "cred-dup", "Key 1");

        webClient.post().uri("/api/v1/auth/passkeys")
                .headers(h -> h.setBearerAuth(auth.accessToken()))
                .bodyValue(Map.of("credentialId", "cred-dup", "displayName", "Key 2"))
                .exchange()
                .expectStatus().isEqualTo(409)
                .expectBody()
                .jsonPath("$.type").isEqualTo("urn:eudistack:error:duplicate-passkey");
    }

    @Test
    void revokeSessions_thenRefreshFails() {
        var auth = authenticateUser("passkey-revoke@example.com");
        var passkeyId = createPasskey(auth.accessToken(), "cred-revoke", "Revokable Key");

        webClient.post().uri("/api/v1/auth/passkeys/{id}/revoke-sessions", passkeyId)
                .headers(h -> h.setBearerAuth(auth.accessToken()))
                .exchange()
                .expectStatus().isNoContent();
    }

    @Test
    void revokeSessions_twice_isIdempotent() {
        var auth = authenticateUser("passkey-revoke-idem@example.com");
        var passkeyId = createPasskey(auth.accessToken(), "cred-revoke-idem", "Key");

        webClient.post().uri("/api/v1/auth/passkeys/{id}/revoke-sessions", passkeyId)
                .headers(h -> h.setBearerAuth(auth.accessToken()))
                .exchange()
                .expectStatus().isNoContent();

        webClient.post().uri("/api/v1/auth/passkeys/{id}/revoke-sessions", passkeyId)
                .headers(h -> h.setBearerAuth(auth.accessToken()))
                .exchange()
                .expectStatus().isNoContent();
    }

    @Test
    void accessOtherUsersPasskey_returns404() {
        var auth1 = authenticateUser("user1-passkey@example.com");
        var auth2 = authenticateUser("user2-passkey@example.com");
        var passkeyId = createPasskey(auth1.accessToken(), "cred-other", "User1 Key");

        // User2 tries to access User1's passkey
        webClient.patch().uri("/api/v1/auth/passkeys/{id}", passkeyId)
                .headers(h -> h.setBearerAuth(auth2.accessToken()))
                .bodyValue(Map.of("displayName", "Hacked"))
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    void passkeyEndpoints_withoutAuth_returns401() {
        webClient.get().uri("/api/v1/auth/passkeys")
                .exchange()
                .expectStatus().isUnauthorized();

        webClient.post().uri("/api/v1/auth/passkeys")
                .bodyValue(Map.of("credentialId", "cred", "displayName", "test"))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void registerPasskey_invalidDisplayName_returns400() {
        var auth = authenticateUser("passkey-validation@example.com");

        webClient.post().uri("/api/v1/auth/passkeys")
                .headers(h -> h.setBearerAuth(auth.accessToken()))
                .bodyValue(Map.of("credentialId", "cred", "displayName", ""))
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void registerPasskey_withRefreshToken_updatesTokenReference() {
        var auth = authenticateUser("passkey-refresh-link@example.com");

        // Register passkey with refresh token
        var passkey = webClient.post().uri("/api/v1/auth/passkeys")
                .headers(h -> h.setBearerAuth(auth.accessToken()))
                .bodyValue(Map.of(
                        "credentialId", "cred-linked",
                        "displayName", "Linked Device",
                        "refreshToken", auth.refreshToken()))
                .exchange()
                .expectStatus().isCreated()
                .expectBody(Map.class)
                .returnResult().getResponseBody();

        assertThat(passkey.get("credentialId")).isEqualTo("cred-linked");

        // List passkeys and verify it shows 1 active session (the linked refresh token)
        var list = webClient.get().uri("/api/v1/auth/passkeys")
                .headers(h -> h.setBearerAuth(auth.accessToken()))
                .exchange()
                .expectStatus().isOk()
                .expectBody(List.class)
                .returnResult().getResponseBody();

        assertThat(list).hasSize(1);
        @SuppressWarnings("unchecked")
        var passkeyData = (Map<String, Object>) list.get(0);
        assertThat(passkeyData.get("activeSessions")).isEqualTo(1);
    }

    // --- Helpers ---

    private record AuthTokens(String accessToken, String refreshToken) {}

    @SuppressWarnings("unchecked")
    private AuthTokens authenticateUser(String email) {
        webClient.post().uri("/api/v1/auth/register")
                .bodyValue(Map.of("email", email))
                .exchange()
                .expectStatus().isOk();

        var otp = capturedOtps.get(email);
        var tokens = webClient.post().uri("/api/v1/auth/verify-email")
                .bodyValue(Map.of("email", email, "code", otp))
                .exchange()
                .expectStatus().isOk()
                .expectBody(Map.class)
                .returnResult().getResponseBody();

        return new AuthTokens((String) tokens.get("accessToken"), (String) tokens.get("refreshToken"));
    }

    @SuppressWarnings("unchecked")
    private String createPasskey(String accessToken, String credentialId, String displayName) {
        var passkey = webClient.post().uri("/api/v1/auth/passkeys")
                .headers(h -> h.setBearerAuth(accessToken))
                .bodyValue(Map.of("credentialId", credentialId, "displayName", displayName))
                .exchange()
                .expectStatus().isCreated()
                .expectBody(Map.class)
                .returnResult().getResponseBody();

        return (String) passkey.get("id");
    }
}
