package com.eudistack.ebw.integration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;

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
        webClient.patch().uri("/api/v1/credentials/" + stored2.get("id") + "/status")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of("status", "SUSPENDED"))
                .exchange()
                .expectStatus().isOk();

        var result = webClient.get().uri("/api/v1/credentials?status=SUSPENDED")
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

        var result = webClient.get().uri("/api/v1/credentials?credential_configuration_id=specific-config-id")
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

        var result = webClient.get().uri("/api/v1/credentials?issuer=https://issuer-alpha.com")
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
        webClient.patch().uri("/api/v1/credentials/" + stored2.get("id") + "/status")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of("status", "SUSPENDED"))
                .exchange()
                .expectStatus().isOk();

        var result = webClient.get().uri("/api/v1/credentials?status=VALID&issuer=https://combined-issuer.com")
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isOk()
                .expectBody(List.class)
                .returnResult().getResponseBody();

        assertThat(result).hasSize(1);
    }

    /**
     * The filter query {@code findAllByUserIdAndFiltersWithoutRaw} (EUDI-040 review W2) still
     * binds {@code user_id = :userId} and MUST NOT leak another user's credentials regardless
     * of the filter values supplied. This test seeds user B with a credential that matches
     * every filter a malicious user A might supply, then verifies that each filtered query
     * run as user A returns an empty list.
     *
     * <p>Also asserts that the projection omits {@code credential_raw} — the filter path
     * uses a different query than the unfiltered list path, so the DTO contract must be
     * independently verified here (the list endpoint shares the same
     * {@code CredentialSummaryResponse} DTO).
     */
    @Test
    @SuppressWarnings("unchecked")
    void filter_doesNotLeakOtherUsersCredentials() {
        var sharedIssuer = "https://shared-leak-test.com";
        var sharedConfigId = "shared-cfg-leak";

        // User B seeds a credential that matches every filter we'll try as user A.
        var userBToken = getAccessToken("user-b-filter-leak-" + System.nanoTime() + "@test.com");
        var credB = CredentialCrudIntegrationTest.buildTestJwt(
                sharedIssuer, "did:example:user-b", "TestCredential", null);
        webClient.post().uri("/api/v1/credentials")
                .header("Authorization", "Bearer " + userBToken)
                .bodyValue(Map.of(
                        "credential_raw", credB,
                        "format", "jwt_vc_json",
                        "credential_configuration_id", sharedConfigId,
                        "kid", "kid-b-" + System.nanoTime()
                ))
                .exchange()
                .expectStatus().isCreated();

        // User A has NO credentials with those attributes — each filter query must return empty.
        assertFilteredListEmpty("/api/credentials?status=VALID");
        assertFilteredListEmpty("/api/credentials?issuer=" + sharedIssuer);
        assertFilteredListEmpty("/api/credentials?credential_configuration_id=" + sharedConfigId);
        assertFilteredListEmpty("/api/credentials?status=VALID&issuer=" + sharedIssuer);
        assertFilteredListEmpty("/api/credentials?status=VALID&issuer=" + sharedIssuer
                + "&credential_configuration_id=" + sharedConfigId);

        // Now user A seeds one credential and re-runs a filtered query: the projection must
        // omit credential_raw (the filter query path uses findAllByUserIdAndFiltersWithoutRaw).
        storeCredential("jwt_vc_json", "config-a-owned", "https://issuer-a-owned.com");
        var ownList = webClient.get().uri("/api/v1/credentials?status=VALID")
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isOk()
                .expectBody(List.class)
                .returnResult().getResponseBody();

        assertThat(ownList).hasSize(1);
        var first = (Map<String, Object>) ownList.get(0);
        assertThat(first).doesNotContainKey("credential_raw");
    }

    private void assertFilteredListEmpty(String uri) {
        var result = webClient.get().uri(uri)
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isOk()
                .expectBody(List.class)
                .returnResult().getResponseBody();
        assertThat(result).as("filter query must not leak other users' credentials: %s", uri).isEmpty();
    }

    @Test
    void filterInvalidStatus_returns400() {
        webClient.get().uri("/api/v1/credentials?status=INVALID_STATUS")
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
        webClient.patch().uri("/api/v1/credentials/" + id + "/status")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of("status", "SUSPENDED"))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.status").isEqualTo("SUSPENDED");

        // SUSPENDED -> VALID (reactivation)
        webClient.patch().uri("/api/v1/credentials/" + id + "/status")
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
        webClient.patch().uri("/api/v1/credentials/" + id + "/status")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of("status", "REVOKED"))
                .exchange()
                .expectStatus().isOk();

        // REVOKED -> VALID (should fail)
        webClient.patch().uri("/api/v1/credentials/" + id + "/status")
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
        webClient.patch().uri("/api/v1/credentials/" + id + "/status")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of("status", "EXPIRED"))
                .exchange()
                .expectStatus().isOk();

        // EXPIRED -> VALID (should fail)
        webClient.patch().uri("/api/v1/credentials/" + id + "/status")
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
        webClient.get().uri("/api/v1/credentials/" + id)
                .header("Authorization", "Bearer " + otherToken)
                .exchange()
                .expectStatus().isNotFound();

        // Try to update status
        webClient.patch().uri("/api/v1/credentials/" + id + "/status")
                .header("Authorization", "Bearer " + otherToken)
                .bodyValue(Map.of("status", "REVOKED"))
                .exchange()
                .expectStatus().isNotFound();

        // Try to delete
        webClient.delete().uri("/api/v1/credentials/" + id)
                .header("Authorization", "Bearer " + otherToken)
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    void noToken_returns401() {
        webClient.get().uri("/api/v1/credentials")
                .exchange()
                .expectStatus().isUnauthorized();

        webClient.post().uri("/api/v1/credentials")
                .bodyValue(Map.of("credential_raw", "x", "format", "jwt_vc_json",
                        "credential_configuration_id", "x", "kid", "x"))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void storeMalformedJwt_returns400() {
        webClient.post().uri("/api/v1/credentials")
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

    /**
     * {@code validateFormat} runs inside the reactive chain (EUDI-040 review W3), so the
     * resulting {@code UnsupportedFormatException} must still flow through
     * {@code GlobalExceptionHandler} and emerge as a typed RFC 7807 {@code ProblemDetail}
     * body — not as a generic 500 or a reactor-wrapped error surface. Asserting the
     * {@code type} URN guards the exception-handler plumbing after the refactor.
     */
    @Test
    @SuppressWarnings("unchecked")
    void storeUnsupportedFormat_returns400() {
        var body = webClient.post().uri("/api/v1/credentials")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of(
                        "credential_raw", "anything",
                        "format", "unknown_format",
                        "credential_configuration_id", "config-unknown",
                        "kid", "kid-unknown"
                ))
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody(Map.class)
                .returnResult().getResponseBody();

        assertThat(body).containsKeys("type", "status", "title", "detail");
        assertThat(body.get("type")).isEqualTo("urn:eudistack:error:unsupported-format");
        assertThat(body.get("status")).isEqualTo(400);
    }

    @Test
    void emptyCredentialList_returns200WithEmptyArray() {
        // New user with no credentials
        var freshToken = getAccessToken("empty-user-" + System.nanoTime() + "@test.com");

        var result = webClient.get().uri("/api/v1/credentials")
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

        webClient.delete().uri("/api/v1/credentials/" + id)
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isNoContent();

        webClient.get().uri("/api/v1/credentials/" + id)
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isNotFound();

        webClient.patch().uri("/api/v1/credentials/" + id + "/status")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of("status", "REVOKED"))
                .exchange()
                .expectStatus().isNotFound();

        webClient.delete().uri("/api/v1/credentials/" + id)
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isNotFound();
    }

    // --- Enumeration-prevention (RF-014) ---

    /**
     * Accessing another user's credential (exists but not owned) and accessing a
     * nonexistent credential MUST produce structurally identical 404 responses so that
     * an attacker cannot distinguish the two cases and enumerate valid credential ids.
     * Applies to GET, PATCH /status and DELETE.
     *
     * <p>Note: the RFC 7807 {@code instance} field echoes the request URI, so it
     * legitimately differs between the two requests (the attacker already knows the URL
     * they sent). The leak-sensitive signal is carried by {@code type}, {@code title},
     * {@code status}, {@code detail} and any extension properties — those MUST match.
     */
    @Test
    @SuppressWarnings("unchecked")
    void enumerationPrevention_otherUserVsNonexistent_sameResponseShape() {
        // User A stores a credential
        var storedA = storeCredential("jwt_vc_json", "config-enum-1", "https://issuer.com");
        var credAId = (String) storedA.get("id");

        // User B (different email) obtains a token
        var userBToken = getAccessToken("user-b-enum-" + System.nanoTime() + "@test.com");

        var nonexistentId = UUID.randomUUID().toString();

        // GET — other user's credential
        var getOtherUser = webClient.get().uri("/api/v1/credentials/" + credAId)
                .header("Authorization", "Bearer " + userBToken)
                .exchange()
                .expectStatus().isNotFound()
                .expectBody(Map.class)
                .returnResult().getResponseBody();

        // GET — nonexistent credential
        var getNonexistent = webClient.get().uri("/api/v1/credentials/" + nonexistentId)
                .header("Authorization", "Bearer " + userBToken)
                .exchange()
                .expectStatus().isNotFound()
                .expectBody(Map.class)
                .returnResult().getResponseBody();

        // Leak-sensitive fields (everything except the request-URI echo in `instance`)
        // MUST be identical — no enumeration signal leaks.
        assertSameShapeExceptInstance(getOtherUser, getNonexistent);
        assertThat(getOtherUser).containsKeys("type", "title", "status", "detail");
        assertThat(getOtherUser.get("status")).isEqualTo(404);

        // PATCH /status — other user's credential
        var patchOtherUser = webClient.patch().uri("/api/v1/credentials/" + credAId + "/status")
                .header("Authorization", "Bearer " + userBToken)
                .bodyValue(Map.of("status", "SUSPENDED"))
                .exchange()
                .expectStatus().isNotFound()
                .expectBody(Map.class)
                .returnResult().getResponseBody();

        // PATCH /status — nonexistent credential
        var patchNonexistent = webClient.patch().uri("/api/v1/credentials/" + nonexistentId + "/status")
                .header("Authorization", "Bearer " + userBToken)
                .bodyValue(Map.of("status", "SUSPENDED"))
                .exchange()
                .expectStatus().isNotFound()
                .expectBody(Map.class)
                .returnResult().getResponseBody();

        assertSameShapeExceptInstance(patchOtherUser, patchNonexistent);
        assertThat(patchOtherUser.get("status")).isEqualTo(404);

        // DELETE — other user's credential
        var deleteOtherUser = webClient.delete().uri("/api/v1/credentials/" + credAId)
                .header("Authorization", "Bearer " + userBToken)
                .exchange()
                .expectStatus().isNotFound()
                .expectBody(Map.class)
                .returnResult().getResponseBody();

        // DELETE — nonexistent credential
        var deleteNonexistent = webClient.delete().uri("/api/v1/credentials/" + nonexistentId)
                .header("Authorization", "Bearer " + userBToken)
                .exchange()
                .expectStatus().isNotFound()
                .expectBody(Map.class)
                .returnResult().getResponseBody();

        assertSameShapeExceptInstance(deleteOtherUser, deleteNonexistent);
        assertThat(deleteOtherUser.get("status")).isEqualTo(404);
    }

    @SuppressWarnings("unchecked")
    private static void assertSameShapeExceptInstance(Map<?, ?> a, Map<?, ?> b) {
        var aCopy = new java.util.HashMap<Object, Object>(a);
        var bCopy = new java.util.HashMap<Object, Object>(b);
        aCopy.remove("instance");
        bCopy.remove("instance");
        assertThat(aCopy).isEqualTo(bCopy);
    }

    // --- Helpers ---

    @SuppressWarnings("unchecked")
    private Map<String, Object> storeCredential(String format, String configId, String issuer) {
        var credentialRaw = CredentialCrudIntegrationTest.buildTestJwt(
                issuer, "did:example:subject", "TestCredential", null);

        return webClient.post().uri("/api/v1/credentials")
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
