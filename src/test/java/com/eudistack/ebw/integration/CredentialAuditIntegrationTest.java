package com.eudistack.ebw.integration;

import com.eudistack.ebw.integration.CredentialCrudIntegrationTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.r2dbc.core.DatabaseClient;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class CredentialAuditIntegrationTest extends IntegrationTestBase {

    @Autowired
    private DatabaseClient databaseClient;

    private String accessToken;

    @BeforeEach
    void setUp() {
        accessToken = getAccessToken("cred-audit-" + System.nanoTime() + "@test.com");
    }

    @Test
    void statusChanged_auditEventIncludesEntityHashMatchingCreated() {
        // Store: produces a CREATED audit row with entity_hash
        var credentialRaw = CredentialCrudIntegrationTest.buildTestJwt(
                "https://issuer.example.com", "did:example:subject",
                "LEARCredentialEmployee", null);

        var stored = webClient.post().uri("/api/v1/credentials")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of(
                        "credential_raw", credentialRaw,
                        "format", "jwt_vc_json",
                        "credential_configuration_id", "config-audit-1",
                        "kid", "kid-audit-" + System.nanoTime()
                ))
                .exchange()
                .expectStatus().isCreated()
                .expectBody(Map.class)
                .returnResult().getResponseBody();
        var id = (String) stored.get("id");

        // Patch status VALID -> SUSPENDED: produces a STATUS_CHANGED audit row
        webClient.patch().uri("/api/v1/credentials/" + id + "/status")
                .header("Authorization", "Bearer " + accessToken)
                .bodyValue(Map.of("status", "SUSPENDED"))
                .exchange()
                .expectStatus().isOk();

        // Query audit rows for this credential
        List<Map<String, Object>> rows = databaseClient.sql(
                        "SELECT action, metadata FROM ebw.audit_log "
                                + "WHERE entity_type = 'credential' AND entity_id = $1::uuid "
                                + "ORDER BY created_at ASC")
                .bind("$1", id)
                .fetch()
                .all()
                .collectList()
                .block();

        assertThat(rows).hasSize(2);

        var createdMetadata = (String) rows.get(0).get("metadata");
        var statusChangedMetadata = (String) rows.get(1).get("metadata");

        assertThat(rows.get(0).get("action")).isEqualTo("CREATED");
        assertThat(rows.get(1).get("action")).isEqualTo("STATUS_CHANGED");

        assertThat(createdMetadata).contains("\"entity_hash\":\"sha256:");
        assertThat(statusChangedMetadata).contains("\"entity_hash\":\"sha256:");

        var createdHash = extractEntityHash(createdMetadata);
        var statusChangedHash = extractEntityHash(statusChangedMetadata);
        assertThat(statusChangedHash)
                .as("STATUS_CHANGED entity_hash must match CREATED entity_hash for the same credential")
                .isEqualTo(createdHash);
    }

    private static String extractEntityHash(String metadataJson) {
        var marker = "\"entity_hash\":\"";
        var start = metadataJson.indexOf(marker);
        if (start < 0) return null;
        start += marker.length();
        var end = metadataJson.indexOf('"', start);
        return metadataJson.substring(start, end);
    }
}
