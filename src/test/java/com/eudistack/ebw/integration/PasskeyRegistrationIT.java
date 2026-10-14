package com.eudistack.ebw.integration;

import com.eudistack.ebw.support.SoftwareAuthenticator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * EUD-8 registration (FR-03 to FR-11): account created when the code is verified, registration
 * ticket instead of a session, verified passkey registration with the full credential record,
 * single-use ceremonies and tickets, PRF check with passkey custody and new passkey notice.
 */
class PasskeyRegistrationIT extends IntegrationTestBase {

    @BeforeEach
    void setUp() {
        setupEmailCapture();
        capturedOtps.clear();
    }

    private static String email(String name) {
        return name + "-" + System.nanoTime() + "@example.com";
    }

    @Test
    void verifyEmail_newEmail_createsAccountAndReturnsTicketWithoutSession() {
        var email = email("reg-ticket");

        var body = authClient().verifyEmail(email);

        assertThat(body).containsOnlyKeys("registrationTicket", "expiresIn", "hasPasskeys");
        assertThat(body.get("expiresIn")).isEqualTo(300);
        assertThat(body.get("hasPasskeys")).isEqualTo(false);
        var account = query("SELECT webauthn_user_handle FROM wallet_user WHERE email = '" + email + "'");
        assertThat(account).singleElement()
                .satisfies(row -> assertThat((byte[]) row.get("webauthn_user_handle")).hasSize(32));
    }

    @Test
    @SuppressWarnings("unchecked")
    void registrationOptions_validTicket_followTheContract() {
        var email = email("reg-options");
        var auth = authClient();

        var options = auth.registrationOptions(auth.ticket(email));

        var publicKey = (Map<String, Object>) options.get("publicKey");
        assertThat(options.get("ceremonyId")).isNotNull();
        assertThat((Map<String, Object>) publicKey.get("rp")).containsEntry("id", TEST_RP_ID)
                .containsEntry("name", "EUDIStack Wallet");
        assertThat((Map<String, Object>) publicKey.get("user")).containsEntry("name", email)
                .containsEntry("displayName", email);
        assertThat((List<Map<String, Object>>) publicKey.get("pubKeyCredParams"))
                .extracting(p -> p.get("alg")).containsExactly(-7, -8, -257);
        assertThat((List<String>) publicKey.get("hints")).containsExactly("hybrid", "security-key", "client-device");
        assertThat(publicKey).containsEntry("timeout", 120000).containsEntry("attestation", "none")
                .doesNotContainKey("extensions");
        assertThat((Map<String, Object>) publicKey.get("authenticatorSelection"))
                .containsEntry("residentKey", "required").containsEntry("userVerification", "required");
    }

    @Test
    void registerPasskey_verifiedResponse_storesCredentialRecordAndOpensSession() {
        var email = email("reg-record");
        var authenticator = new SoftwareAuthenticator(TEST_ORIGIN);

        var session = authClient().signUp(email, authenticator);

        assertThat(session.accessToken()).isNotBlank();
        assertThat(session.setCookie()).startsWith("__Host-wallet_refresh=").contains("HttpOnly").contains("Secure")
                .contains("SameSite=Strict").contains("Path=/;").contains("Max-Age=").doesNotContain("Domain=");
        var passkey = query("SELECT * FROM user_passkey WHERE id = '" + session.passkeyId() + "'").get(0);
        assertThat(passkey.get("credential_id")).isEqualTo(authenticator.credentialIdBase64Url());
        assertThat((byte[]) passkey.get("attested_credential_data")).isNotEmpty();
        assertThat(passkey).containsEntry("backup_eligible", true).containsEntry("backup_state", true)
                .containsEntry("uv_initialized", true).containsEntry("prf_enabled", true)
                .containsEntry("attestation_format", "none");
    }

    @Test
    void registerPasskey_ticketUsedTwice_secondIsRejected() {
        var auth = authClient();
        var ticket = auth.ticket(email("reg-ticket-once"));
        auth.registerPasskey(ticket, new SoftwareAuthenticator(TEST_ORIGIN));

        auth.registrationOptionsSpec(ticket).expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.type").isEqualTo("invalid_ticket");
    }

    @Test
    void registerPasskey_withoutTicket_isRejected() {
        authClient().registrationOptionsSpec(null).expectStatus().isUnauthorized()
                .expectHeader().contentType("application/problem+json")
                .expectBody().jsonPath("$.type").isEqualTo("invalid_ticket");
    }

    @Test
    @SuppressWarnings("unchecked")
    void registerPasskey_ceremonyUsedTwice_secondIsRejected() {
        var auth = authClient();
        var email = email("reg-ceremony-once");
        var options = auth.registrationOptions(auth.ticket(email));
        var credential = new SoftwareAuthenticator(TEST_ORIGIN).register((Map<String, Object>) options.get("publicKey"));
        // The first attempt fails after consuming the ceremony (wrong origin), the retry cannot reuse it.
        var foreign = new SoftwareAuthenticator("https://evil.example.com")
                .register((Map<String, Object>) options.get("publicKey"));
        var ticket = auth.ticket(email);
        auth.registerSpec(ticket, options.get("ceremonyId"), foreign, true, null).expectStatus().isBadRequest()
                .expectBody().jsonPath("$.type").isEqualTo("registration_failed");

        auth.registerSpec(ticket, options.get("ceremonyId"), credential, true, null).expectStatus().isBadRequest()
                .expectBody().jsonPath("$.type").isEqualTo("registration_failed");
    }

    @Test
    @SuppressWarnings("unchecked")
    void registerPasskey_expiredCeremony_isRejected() {
        var auth = authClient();
        var ticket = auth.ticket(email("reg-ceremony-expired"));
        var options = auth.registrationOptions(ticket);
        sql("UPDATE webauthn_ceremony SET expires_at = now() - interval '1 second' WHERE id = '"
                + options.get("ceremonyId") + "'");
        var credential = new SoftwareAuthenticator(TEST_ORIGIN).register((Map<String, Object>) options.get("publicKey"));

        auth.registerSpec(ticket, options.get("ceremonyId"), credential, true, null).expectStatus().isBadRequest()
                .expectBody().jsonPath("$.type").isEqualTo("registration_failed");
    }

    @Test
    void registerPasskey_withoutUserVerification_isRejectedAndNothingStored() {
        var auth = authClient();
        var email = email("reg-no-uv");

        auth.registerPasskeySpec(auth.ticket(email), new SoftwareAuthenticator(TEST_ORIGIN).withUserVerified(false),
                        null)
                .expectStatus().isBadRequest().expectBody().jsonPath("$.type").isEqualTo("registration_failed");

        assertThat(query("SELECT p.id FROM user_passkey p JOIN wallet_user u ON u.id = p.user_id WHERE u.email = '"
                + email + "'")).isEmpty();
    }

    @Test
    void registerPasskey_sameCredentialTwiceInTenant_isRejected() {
        var auth = authClient();
        var authenticator = new SoftwareAuthenticator(TEST_ORIGIN);
        auth.signUp(email("reg-dup-a"), authenticator);

        auth.registerPasskeySpec(auth.ticket(email("reg-dup-b")), authenticator, null)
                .expectStatus().isBadRequest().expectBody().jsonPath("$.type").isEqualTo("registration_failed");
    }

    @Test
    @SuppressWarnings("unchecked")
    void registrationOptions_accountWithPasskey_excludesIt() {
        var auth = authClient();
        var email = email("reg-exclude");
        var authenticator = new SoftwareAuthenticator(TEST_ORIGIN);
        auth.signUp(email, authenticator);

        var options = auth.registrationOptions(auth.ticket(email));

        assertThat((List<Map<String, Object>>) ((Map<String, Object>) options.get("publicKey")).get("excludeCredentials"))
                .extracting(c -> c.get("id")).containsExactly(authenticator.credentialIdBase64Url());
    }

    @Test
    void registerPasskey_secondPasskeyOfTheAccount_emailsTheHolder() {
        var auth = authClient();
        var email = email("reg-notice");
        auth.signUp(email, new SoftwareAuthenticator(TEST_ORIGIN));
        verify(emailSender, never()).sendNewPasskeyNotice(eq(email));

        auth.signUp(email, new SoftwareAuthenticator(TEST_ORIGIN));

        verify(emailSender).sendNewPasskeyNotice(eq(email));
    }

    @Test
    void registerPasskey_passkeyCustodyWithoutPrf_returns422AndStoresNothing() {
        var auth = authClient();
        var email = email("reg-prf");
        var ticket = auth.ticket(email);
        withPasskeyCustody(() -> {
            @SuppressWarnings("unchecked")
            var options = auth.registrationOptions(ticket);
            @SuppressWarnings("unchecked")
            var publicKey = (Map<String, Object>) options.get("publicKey");
            assertThat(publicKey).containsKey("extensions");
            var credential = new SoftwareAuthenticator(TEST_ORIGIN).withPrfEnabled(false).register(publicKey);

            auth.registerSpec(ticket, options.get("ceremonyId"), credential, false, null)
                    .expectStatus().isEqualTo(422)
                    .expectBody().jsonPath("$.type").isEqualTo("passkey_prf_unsupported");
        });

        assertThat(query("SELECT p.id FROM user_passkey p JOIN wallet_user u ON u.id = p.user_id WHERE u.email = '"
                + email + "'")).isEmpty();
    }

    @Test
    void registerPasskey_passkeyCustodyWithPrf_isRegistered() {
        var auth = authClient();
        var email = email("reg-prf-ok");
        withPasskeyCustody(() -> auth.registerPasskeySpec(auth.ticket(email), new SoftwareAuthenticator(TEST_ORIGIN),
                null).expectStatus().isCreated()
                .expectHeader().value(HttpHeaders.SET_COOKIE, c -> assertThat(c).startsWith("__Host-wallet_refresh=")));
    }

    /** Runs with the test tenant in passkey custody (server + passkey-prf), then restores it. */
    static void withPasskeyCustody(Runnable action) {
        sql("INSERT INTO tenant_wallet_profile (tenant, wallet_mode, key_manager) VALUES ('" + TEST_TENANT
                + "', 'server', 'passkey-prf') ON CONFLICT (tenant) DO UPDATE SET wallet_mode = 'server', "
                + "key_manager = 'passkey-prf'");
        try {
            action.run();
        } finally {
            sql("DELETE FROM tenant_wallet_profile WHERE tenant = '" + TEST_TENANT + "'");
        }
    }
}
