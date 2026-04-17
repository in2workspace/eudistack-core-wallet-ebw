package com.eudistack.ebw.integration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class CredentialFilterSecurityIntegrationTest extends IntegrationTestBase {

    private String accessToken;

    @BeforeEach
    void setUp() {
        accessToken = getAccessToken("cred-filter-" + System.nanoTime() + "@test.com");
    }

    // --- Filtering tests ---

    @Test
    void filterByStatus_returnsOnlyMatching() {
        storeCredential("jwt_vc_json", "config-a", "https://issuer-a.com");
        var stored2 = storeCredential("jwt_vc_json", "config-b", "https://issuer-b.com");

        // Suspend second credential
        webClient.patch().uri("/api/credentials/" + stored2.get("id") + "/status")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of("status", "SUSPENDED"))
                .exchange()
                .expectStatus().isOk();

        var result = webClient.get().uri("/api/credentials?status=SUSPENDED")
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isOk()
                .expectBody(List.class)
                .returnResult().getResponseBody();

        assertThat(result).hasSize(1);
    }

    @Test
    void filterByCredentialConfigId_returnsOnlyMatching() {
        storeCredential("jwt_vc_json", "specific-config-id", "https://issuer.com");
        storeCredential("jwt_vc_json", "other-config-id", "https://issuer.com");

        var result = webClient.get().uri("/api/credentials?credential_configuration_id=specific-config-id")
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isOk()
                .expectBody(List.class)
                .returnResult().getResponseBody();

        assertThat(result).hasSize(1);
    }

    @Test
    void filterByIssuer_returnsOnlyMatching() {
        storeCredential("jwt_vc_json", "config-x", "https://issuer-alpha.com");
        storeCredential("jwt_vc_json", "config-y", "https://issuer-beta.com");

        var result = webClient.get().uri("/api/credentials?issuer=https://issuer-alpha.com")
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isOk()
                .expectBody(List.class)
                .returnResult().getResponseBody();

        assertThat(result).hasSize(1);
    }

    @Test
    void filterCombined_statusAndIssuer() {
        storeCredential("jwt_vc_json", "config-c1", "https://combined-issuer.com");
        var stored2 = storeCredential("jwt_vc_json", "config-c2", "https://combined-issuer.com");

        // Suspend one
        webClient.patch().uri("/api/credentials/" + stored2.get("id") + "/status")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of("status", "SUSPENDED"))
                .exchange()
                .expectStatus().isOk();

        var result = webClient.get().uri("/api/credentials?status=VALID&issuer=https://combined-issuer.com")
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isOk()
                .expectBody(List.class)
                .returnResult().getResponseBody();

        assertThat(result).hasSize(1);
    }

    @Test
    void filterInvalidStatus_returns400() {
        webClient.get().uri("/api/credentials?status=INVALID_STATUS")
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isBadRequest();
    }

    // --- Status transition tests ---

    @Test
    void statusTransition_validToSuspendedAndBack() {
        var stored = storeCredential("jwt_vc_json", "config-trans-1", "https://issuer.com");
        var id = (String) stored.get("id");

        // VALID -> SUSPENDED
        webClient.patch().uri("/api/credentials/" + id + "/status")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of("status", "SUSPENDED"))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.status").isEqualTo("SUSPENDED");

        // SUSPENDED -> VALID (reactivation)
        webClient.patch().uri("/api/credentials/" + id + "/status")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of("status", "VALID"))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.status").isEqualTo("VALID");
    }

    @Test
    void statusTransition_revokedIsTerminal_returns422() {
        var stored = storeCredential("jwt_vc_json", "config-trans-2", "https://issuer.com");
        var id = (String) stored.get("id");

        // VALID -> REVOKED
        webClient.patch().uri("/api/credentials/" + id + "/status")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of("status", "REVOKED"))
                .exchange()
                .expectStatus().isOk();

        // REVOKED -> VALID (should fail)
        webClient.patch().uri("/api/credentials/" + id + "/status")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of("status", "VALID"))
                .exchange()
                .expectStatus().isEqualTo(422);
    }

    @Test
    void statusTransition_expiredIsTerminal_returns422() {
        var stored = storeCredential("jwt_vc_json", "config-trans-3", "https://issuer.com");
        var id = (String) stored.get("id");

        // VALID -> EXPIRED
        webClient.patch().uri("/api/credentials/" + id + "/status")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of("status", "EXPIRED"))
                .exchange()
                .expectStatus().isOk();

        // EXPIRED -> VALID (should fail)
        webClient.patch().uri("/api/credentials/" + id + "/status")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of("status", "VALID"))
                .exchange()
                .expectStatus().isEqualTo(422);
    }

    // --- Security tests ---

    @Test
    void accessOtherUsersCredential_returns404() {
        // Store credential as current user
        var stored = storeCredential("jwt_vc_json", "config-sec-1", "https://issuer.com");
        var id = (String) stored.get("id");

        // Get token for a different user
        var otherToken = getAccessToken("other-user-" + System.nanoTime() + "@test.com");

        // Try to access the credential
        webClient.get().uri("/api/credentials/" + id)
                .header("Authorization", "Bearer " + otherToken)
                .exchange()
                .expectStatus().isNotFound();

        // Try to update status
        webClient.patch().uri("/api/credentials/" + id + "/status")
                .header("Authorization", "Bearer " + otherToken)
                .bodyValue(Map.of("status", "REVOKED"))
                .exchange()
                .expectStatus().isNotFound();

        // Try to delete
        webClient.delete().uri("/api/credentials/" + id)
                .header("Authorization", "Bearer " + otherToken)
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    void noToken_returns401() {
        webClient.get().uri("/api/credentials")
                .exchange()
                .expectStatus().isUnauthorized();

        webClient.post().uri("/api/credentials")
                .bodyValue(Map.of("credential_raw", "x", "format", "jwt_vc_json",
                        "credential_configuration_id", "x", "kid", "x"))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void storeMalformedJwt_returns400() {
        webClient.post().uri("/api/credentials")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of(
                        "credential_raw", "not-a-jwt",
                        "format", "jwt_vc_json",
                        "credential_configuration_id", "config-bad",
                        "kid", "kid-bad"
                ))
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void storeUnsupportedFormat_returns400() {
        webClient.post().uri("/api/credentials")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of(
                        "credential_raw", "anything",
                        "format", "unknown_format",
                        "credential_configuration_id", "config-unknown",
                        "kid", "kid-unknown"
                ))
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void emptyCredentialList_returns200WithEmptyArray() {
        // New user with no credentials
        var freshToken = getAccessToken("empty-user-" + System.nanoTime() + "@test.com");

        var result = webClient.get().uri("/api/credentials")
                .header("Authorization", "Bearer " + freshToken)
                .exchange()
                .expectStatus().isOk()
                .expectBody(List.class)
                .returnResult().getResponseBody();

        assertThat(result).isEmpty();
    }

    @Test
    void deletedCredential_getReturns404() {
        var stored = storeCredential("jwt_vc_json", "config-deleted-1", "https://issuer.com");
        var id = (String) stored.get("id");

        webClient.delete().uri("/api/credentials/" + id)
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isNoContent();

        webClient.get().uri("/api/credentials/" + id)
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isNotFound();

        webClient.patch().uri("/api/credentials/" + id + "/status")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of("status", "REVOKED"))
                .exchange()
                .expectStatus().isNotFound();

        webClient.delete().uri("/api/credentials/" + id)
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isNotFound();
    }

    // --- Helpers ---

    @SuppressWarnings("unchecked")
    private Map<String, Object> storeCredential(String format, String configId, String issuer) {
        var credentialRaw = CredentialCrudIntegrationTest.buildTestJwt(
                issuer, "did:example:subject", "TestCredential", null);

        return webClient.post().uri("/api/credentials")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of(
                        "credential_raw", credentialRaw,
                        "format", format,
                        "credential_configuration_id", configId,
                        "kid", "kid-" + System.nanoTime()
                ))
                .exchange()
                .expectStatus().isCreated()
                .expectBody(Map.class)
                .returnResult().getResponseBody();
    }
}
