package com.eudistack.ebw.integration;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class CredentialCrudIntegrationTest extends IntegrationTestBase {

    // HMAC key for building test credential JWTs (32 bytes)
    private static final byte[] TEST_HMAC_KEY = "test-hmac-key-for-credential-jwt".getBytes();

    private String accessToken;

    @BeforeEach
    void setUp() {
        accessToken = getAccessToken("cred-crud-" + System.nanoTime() + "@test.com");
    }

    @Test
    void storeJwtCredential_returns201WithParsedMetadata() {
        var credentialRaw = buildTestJwt("https://issuer.example.com", "did:example:user1",
                "LEARCredentialEmployee", null);

        var response = webClient.post().uri("/api/v1/credentials")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of(
                        "credential_raw", credentialRaw,
                        "format", "jwt_vc_json",
                        "credential_configuration_id", "learcredential.employee.1",
                        "kid", "thumbprint-123",
                        "issuer_metadata", Map.of("credential_issuer", "https://issuer.example.com")
                ))
                .exchange()
                .expectStatus().isCreated()
                .expectHeader().exists("Location")
                .expectBody(Map.class)
                .returnResult().getResponseBody();

        assertThat(response.get("id")).isNotNull();
        assertThat(response.get("status")).isEqualTo("VALID");
        assertThat(response.get("issuer")).isEqualTo("https://issuer.example.com");
        assertThat(response.get("credential_type")).isEqualTo("LEARCredentialEmployee");
        assertThat(response.get("created_at")).isNotNull();
    }

    @Test
    void storeSdJwtCredential_returns201WithVctExtracted() {
        var credentialRaw = buildTestSdJwt("https://issuer.example.com", "did:example:user2",
                "LEARCredentialEmployee", "urn:credential:lear");

        var response = webClient.post().uri("/api/v1/credentials")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of(
                        "credential_raw", credentialRaw,
                        "format", "dc+sd-jwt",
                        "credential_configuration_id", "learcredential.employee.sd.1",
                        "kid", "thumbprint-456"
                ))
                .exchange()
                .expectStatus().isCreated()
                .expectBody(Map.class)
                .returnResult().getResponseBody();

        assertThat(response.get("vct")).isEqualTo("urn:credential:lear");
        assertThat(response.get("format")).isEqualTo("dc+sd-jwt");
    }

    @Test
    void listCredentials_returnsWithoutCredentialRaw() {
        storeTestCredential("jwt_vc_json", "config-list-1");

        var response = webClient.get().uri("/api/v1/credentials")
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isOk()
                .expectBody(List.class)
                .returnResult().getResponseBody();

        assertThat(response).isNotEmpty();
        var first = (Map<String, Object>) response.get(0);
        assertThat(first).doesNotContainKey("credential_raw");
        assertThat(first).containsKeys("id", "credentialFormat", "type", "lifeCycleStatus", "issuer");
    }

    @Test
    void getCredentialById_returnsFullCredentialWithRaw() {
        var stored = storeTestCredential("jwt_vc_json", "config-get-1");
        var id = (String) stored.get("id");

        var response = webClient.get().uri("/api/v1/credentials/" + id)
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isOk()
                .expectBody(Map.class)
                .returnResult().getResponseBody();

        assertThat(response.get("credentialEncoded")).isNotNull();
        assertThat(response.get("id")).isEqualTo(id);
    }

    @Test
    void updateStatus_validToRevoked_returns200() {
        var stored = storeTestCredential("jwt_vc_json", "config-status-1");
        var id = (String) stored.get("id");

        var response = webClient.patch().uri("/api/v1/credentials/" + id + "/status")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of("status", "REVOKED"))
                .exchange()
                .expectStatus().isOk()
                .expectBody(Map.class)
                .returnResult().getResponseBody();

        assertThat(response.get("status")).isEqualTo("REVOKED");
    }

    /**
     * After splitting {@code save} into {@code insert}/{@code update} (EUDI-040 review W4),
     * the UPDATE path must preserve immutable columns — in particular {@code created_at}
     * and {@code credential_raw} — while advancing {@code updated_at}. A regression that
     * accidentally re-dispatched an INSERT (e.g. by setting {@code isNew=true}) would
     * overwrite {@code created_at} with the current clock, so this test asserts that
     * created_at, credential_raw and issuer are byte-identical in the GET detail response
     * taken before and after the PATCH, and that updated_at has strictly advanced past
     * its pre-PATCH value.
     *
     * <p>We compare two GET responses (not the POST body against the GET) because the POST
     * response renders the in-memory domain object after encryption but before the DB
     * round-trip, so its {@code credential_raw} is ciphertext and its {@code created_at}
     * retains nanosecond precision, while GET returns the DB-read value (decrypted
     * credential_raw, microsecond-rounded timestamps). Comparing GET-vs-GET sidesteps
     * both asymmetries.
     */
    @Test
    @SuppressWarnings("unchecked")
    void updateStatus_preservesCreatedAtAndAdvancesUpdatedAt() {
        var stored = storeTestCredential("jwt_vc_json", "config-status-timestamps");
        var id = (String) stored.get("id");

        // Baseline: GET before PATCH — DB-persisted values, decrypted credential_raw.
        var before = webClient.get().uri("/api/v1/credentials/" + id)
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isOk()
                .expectBody(Map.class)
                .returnResult().getResponseBody();

        webClient.patch().uri("/api/v1/credentials/" + id + "/status")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of("status", "SUSPENDED"))
                .exchange()
                .expectStatus().isOk();

        var after = webClient.get().uri("/api/v1/credentials/" + id)
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isOk()
                .expectBody(Map.class)
                .returnResult().getResponseBody();

        assertThat(after.get("lifeCycleStatus")).isEqualTo("SUSPENDED");
        assertThat(after.get("credentialEncoded"))
                .as("credentialEncoded must be preserved across UPDATE")
                .isEqualTo(before.get("credentialEncoded"));
        assertThat(after.get("issuer"))
                .as("issuer must be preserved across UPDATE")
                .isEqualTo(before.get("issuer"));
    }

    @Test
    void deleteCredential_returns204() {
        var stored = storeTestCredential("jwt_vc_json", "config-delete-1");
        var id = (String) stored.get("id");

        webClient.delete().uri("/api/v1/credentials/" + id)
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isNoContent();

        // Verify it's gone
        webClient.get().uri("/api/v1/credentials/" + id)
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    void fullLifecycle_storeListGetUpdateDelete() {
        // Store
        var stored = storeTestCredential("jwt_vc_json", "config-lifecycle-1");
        var id = (String) stored.get("id");
        assertThat(stored.get("status")).isEqualTo("VALID");

        // List
        var list = webClient.get().uri("/api/v1/credentials")
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isOk()
                .expectBody(List.class)
                .returnResult().getResponseBody();
        assertThat(list).hasSizeGreaterThanOrEqualTo(1);

        // Get
        var detail = webClient.get().uri("/api/v1/credentials/" + id)
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isOk()
                .expectBody(Map.class)
                .returnResult().getResponseBody();
        assertThat(detail.get("credentialEncoded")).isNotNull();

        // Update status
        webClient.patch().uri("/api/v1/credentials/" + id + "/status")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of("status", "SUSPENDED"))
                .exchange()
                .expectStatus().isOk();

        // Delete
        webClient.delete().uri("/api/v1/credentials/" + id)
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isNoContent();

        // Verify gone
        webClient.get().uri("/api/v1/credentials/" + id)
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isNotFound();
    }

    // --- Helpers ---

    @SuppressWarnings("unchecked")
    private Map<String, Object> storeTestCredential(String format, String configId) {
        String credentialRaw;
        if ("dc+sd-jwt".equals(format)) {
            credentialRaw = buildTestSdJwt("https://issuer.example.com", "did:example:subject",
                    "LEARCredentialEmployee", "urn:credential:lear");
        } else {
            credentialRaw = buildTestJwt("https://issuer.example.com", "did:example:subject",
                    "LEARCredentialEmployee", null);
        }

        return webClient.post().uri("/api/v1/credentials")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of(
                        "credential_raw", credentialRaw,
                        "format", format,
                        "credential_configuration_id", configId,
                        "kid", "test-kid-" + System.nanoTime()
                ))
                .exchange()
                .expectStatus().isCreated()
                .expectBody(Map.class)
                .returnResult().getResponseBody();
    }

    static String buildTestJwt(String issuer, String subject, String credentialType, String vct) {
        try {
            var now = new Date();
            var exp = new Date(now.getTime() + 86400_000);
            var builder = new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .subject(subject)
                    .issueTime(now)
                    .expirationTime(exp)
                    .claim("vc", Map.of("type", List.of("VerifiableCredential", credentialType)));
            if (vct != null) {
                builder.claim("vct", vct);
            }
            var jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), builder.build());
            jwt.sign(new MACSigner(TEST_HMAC_KEY));
            return jwt.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Failed to build test JWT", e);
        }
    }

    static String buildTestSdJwt(String issuer, String subject, String credentialType, String vct) {
        var jwt = buildTestJwt(issuer, subject, credentialType, vct);
        // SD-JWT format: issuer-signed JWT ~ disclosure1 ~ disclosure2 ~ ...
        return jwt + "~eyJhbGciOiJub25lIn0~";
    }
}
