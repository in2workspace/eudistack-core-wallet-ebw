package com.eudistack.ebw.integration;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.r2dbc.core.DatabaseClient;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * EUD-104 (US-04): a brand-new device completing the SAME onboarding pipeline
 * (register -> verify-email -> passkeys) as an ALREADY-existing account MUST
 * associate to that account instead of creating a duplicate.
 *
 * <p>There is no dedicated {@code /add-device} endpoint (AD-1 in technical-design.md):
 * "new device" is detected client-side purely by the absence of a local passkey
 * ({@code !prfService.hasPasskey()}), so from the backend's point of view this is
 * exactly the same request sequence as {@link RegisterPasskeyFlowIT}, just run twice
 * for the same email with two different {@code credentialId}s. This is the delta
 * EUD-104 is about: proving the find-or-create outcome holds for a SECOND
 * passkey/device (AC-01/AC-02/AC-04), not just the first (EUD-103).
 *
 * <p>Deliberately distinct from {@code AuthFlowIntegrationTest.reAuthentication_existingUser_*}
 * (EC-04 frontier): that test re-verifies on a device that already has a local passkey and
 * never calls {@code POST /passkeys} again, so it only proves "no duplicate account on
 * re-auth" — it does NOT prove a second passkey/device gets associated. That is exactly
 * what this IT adds.
 */
class SecondDeviceAssociationIT extends IntegrationTestBase {

    @Autowired
    private DatabaseClient databaseClient;

    @BeforeEach
    void setUp() {
        setupEmailCapture();
        capturedOtps.clear();
    }

    @Test
    void secondDevice_sameEmail_associatesToExistingAccount_noDuplicateAccount() {
        var email = "second-device-" + System.nanoTime() + "@example.com";
        var credentialD1 = "cred-d1-" + System.nanoTime();
        var credentialD2 = "cred-d2-" + System.nanoTime();

        // Device 1 — first alta (EUD-103's own outcome): register -> verify -> passkey.
        var accessTokenD1 = registerVerifyAndCreatePasskey(email, credentialD1, "Laura's Laptop");
        var userId = fetchUserId(email);
        assertThat(userId).as("account must exist after D1's alta").isNotNull();

        // Device 2 — this Story's outcome: a brand-new device, no local passkey, SAME
        // email. The frontend detects this state purely via EC-01 (!hasPasskey()); the
        // backend sees the identical register/verify/passkeys sequence as D1.
        var accessTokenD2 = registerVerifyAndCreatePasskey(email, credentialD2, "Laura's iPhone");
        assertThat(accessTokenD2)
                .as("each device session gets its own token pair")
                .isNotEqualTo(accessTokenD1);

        // AC-02: exactly one account row for E — associating D2 must not duplicate it.
        assertThat(countUsersByEmail(email)).isEqualTo(1L);

        // AC-01 / AC-04: both passkeys persisted under the SAME account; D1 untouched.
        var d1Row = fetchPasskeyByCredentialId(credentialD1);
        var d2Row = fetchPasskeyByCredentialId(credentialD2);
        assertThat(d1Row).as("D1 must still be registered after associating D2").isNotNull();
        assertThat(d2Row).as("D2 must be persisted").isNotNull();
        assertThat(d1Row.get("user_id")).isEqualTo(userId);
        assertThat(d2Row.get("user_id")).isEqualTo(userId);
        assertThat(d1Row.get("display_name")).isEqualTo("Laura's Laptop");
        assertThat(d2Row.get("display_name")).isEqualTo("Laura's iPhone");

        assertThat(countPasskeysByUserId(userId)).isGreaterThanOrEqualTo(2L);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private String registerVerifyAndCreatePasskey(String email, String credentialId, String displayName) {
        webClient.post().uri("/api/v1/auth/register")
                .bodyValue(Map.of("email", email))
                .exchange()
                .expectStatus().isOk();

        var otp = capturedOtps.get(email);
        assertThat(otp).as("OTP must have been captured for " + email).isNotNull();

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
                        "credentialId", credentialId,
                        "displayName", displayName))
                .exchange()
                .expectStatus().isCreated();

        return accessToken;
    }

    // Unqualified table names — resolved via search_path; direct DatabaseClient calls
    // bypass the X-Tenant/TenantDomainWebFilter pipeline, so the tenant is supplied
    // explicitly via contextWrite (same pattern as RegisterPasskeyFlowIT / AuthFlowIntegrationTest).

    private UUID fetchUserId(String email) {
        var row = databaseClient.sql("SELECT id FROM wallet_user WHERE email = $1")
                .bind("$1", email)
                .fetch()
                .one()
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TEST_TENANT))
                .block();
        return (UUID) row.get("id");
    }

    private long countUsersByEmail(String email) {
        return databaseClient.sql("SELECT COUNT(*) AS c FROM wallet_user WHERE email = $1")
                .bind("$1", email)
                .fetch()
                .one()
                .map(row -> (Long) row.get("c"))
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TEST_TENANT))
                .block();
    }

    private long countPasskeysByUserId(UUID userId) {
        return databaseClient.sql("SELECT COUNT(*) AS c FROM user_passkey WHERE user_id = $1")
                .bind("$1", userId)
                .fetch()
                .one()
                .map(row -> (Long) row.get("c"))
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TEST_TENANT))
                .block();
    }

    private Map<String, Object> fetchPasskeyByCredentialId(String credentialId) {
        return databaseClient.sql("SELECT user_id, display_name FROM user_passkey WHERE credential_id = $1")
                .bind("$1", credentialId)
                .fetch()
                .one()
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TEST_TENANT))
                .block();
    }
}
