package com.eudistack.ebw.integration;

import com.eudistack.ebw.application.workflow.ExpireOnboardingWorkflow;
import com.eudistack.ebw.domain.model.AccountCreatedNotice;
import com.eudistack.ebw.domain.model.OnboardingAlert;
import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.infrastructure.configuration.TenantDomainWebFilter;
import com.eudistack.ebw.support.FakeVerifierServer;
import com.eudistack.ebw.support.SoftwareAuthenticator;
import com.eudistack.ebw.support.TestSystemTokens;
import com.eudistack.ebw.support.WalletAuthClient;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;

/**
 * End-to-end onboarding ticket flow on a running service with PostgreSQL and a simulated tenant
 * Verifier (EUD-315 task 11, first part): the ticket request with system tokens, the redemption
 * and the restricted onboarding mode. Two tenants: {@link #TEST_TENANT}, with onboarding tickets
 * and mode {@code open}, and {@link #RESTRICTED_TENANT}, in mode {@code restricted} without
 * onboarding tickets.
 */
class OnboardingTicketIT extends IntegrationTestBase {

    private static final String RESTRICTED_TENANT = "onboardingb";
    private static final String RESTRICTED_SCHEMA = RESTRICTED_TENANT + "_business_wallet";
    private static final String DISABLED_TENANT = "onboardingc";
    private static final String RESTRICTED_ORIGIN = "https://" + RESTRICTED_TENANT + ".eudistack.test";
    private static final String SIGNUP_URL = "https://portal.onboardingb.example/";
    private static final String SECURITY_CONTACT = "security@integrationtest.example";
    private static final String PUBLIC_HOST = TEST_TENANT + ".eudistack.test";
    private static final String ISSUER = "https://" + PUBLIC_HOST + "/verifier";
    private static final String OFFER =
            "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Fcredential-offer%2F3f2a";

    private static final TestSystemTokens VERIFIER_KEYS = new TestSystemTokens();
    private static final FakeVerifierServer VERIFIER = new FakeVerifierServer(VERIFIER_KEYS.publicJwks());

    @Autowired private ExpireOnboardingWorkflow expireOnboardingWorkflow;

    static {
        configureTenant(TEST_TENANT + "_business_wallet", Map.of(
                "ebw.onboarding.enabled", "true",
                "ebw.onboarding.mode", "open",
                "ebw.onboarding.security_contact", SECURITY_CONTACT));
        provisionSchema(RESTRICTED_SCHEMA);
        configureTenant(RESTRICTED_SCHEMA, Map.of(
                "ebw.webauthn.rp_id", RESTRICTED_TENANT + ".eudistack.test",
                "ebw.webauthn.origins", RESTRICTED_ORIGIN,
                "ebw.onboarding.enabled", "true",
                "ebw.onboarding.mode", "restricted",
                "ebw.onboarding.signup_url", SIGNUP_URL));
        provisionSchema(DISABLED_TENANT + "_business_wallet");
        configureTenant(DISABLED_TENANT + "_business_wallet", Map.of(
                "ebw.webauthn.rp_id", DISABLED_TENANT + ".eudistack.test",
                "ebw.webauthn.origins", "https://" + DISABLED_TENANT + ".eudistack.test"));
    }

    @DynamicPropertySource
    static void verifierProperties(DynamicPropertyRegistry registry) {
        registry.add("ebw.verifier.internal-url", VERIFIER::internalUrl);
    }

    // ------------------------------------------------------------------ fixtures

    private static void provisionSchema(String schema) {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute("CREATE SCHEMA IF NOT EXISTS " + schema);
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        Flyway.configure().dataSource(postgres.getJdbcUrl(), "test", "test").locations("classpath:db/tenant")
                .defaultSchema(schema).schemas(schema).table("flyway_schema_history").baselineOnMigrate(true)
                .load().migrate();
    }

    private static void configureTenant(String schema, Map<String, String> values) {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            for (var entry : values.entrySet()) {
                var statement = conn.prepareStatement("INSERT INTO " + schema + ".tenant_config (config_key, config_value)"
                        + " VALUES (?, ?) ON CONFLICT (config_key) DO UPDATE SET config_value = EXCLUDED.config_value");
                statement.setString(1, entry.getKey());
                statement.setString(2, entry.getValue());
                statement.execute();
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    private static long count(String schema, String where) {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test");
             var result = conn.createStatement().executeQuery("SELECT count(*) FROM " + schema + "." + where)) {
            result.next();
            return result.getLong(1);
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    private static long countInTestTenant(String where) {
        return count(TEST_TENANT + "_business_wallet", where);
    }

    private static String email(String name) {
        return name + "-" + System.nanoTime() + "@example.com";
    }

    private static String adminToken() {
        return VERIFIER_KEYS.token(ISSUER, TEST_TENANT);
    }

    private WebTestClient.ResponseSpec requestTicket(String token, Map<String, Object> body) {
        return webClient.post().uri("/api/v1/onboarding-tickets")
                .header("X-Forwarded-Proto", "https")
                .header("X-Forwarded-Host", PUBLIC_HOST)
                .headers(h -> {
                    if (token != null) {
                        h.setBearerAuth(token);
                    }
                })
                .bodyValue(body)
                .exchange();
    }

    /** The ticket of a new onboarding address for {@code email}, with the offer. */
    private String ticketFor(String email) {
        var url = (String) requestTicket(adminToken(), Map.of("email", email, "credentialOffer", OFFER))
                .expectStatus().isCreated()
                .expectBody(Map.class).returnResult().getResponseBody().get("onboardingUrl");
        return url.substring(url.indexOf('#') + 1);
    }

    private WebTestClient.ResponseSpec redeem(String ticket, String tenant, String accessToken) {
        return redeem(ticket, tenant, accessToken, null);
    }

    /**
     * @param forwardedFor {@code X-Forwarded-For} as our proxies send it; {@code null} for the local address.
     *                     The rate limiter remembers blocked addresses in memory, so a test that exhausts a
     *                     budget uses its own address and does not block the other tests.
     */
    private WebTestClient.ResponseSpec redeem(String ticket, String tenant, String accessToken, String forwardedFor) {
        return webClient.post().uri("/api/v1/auth/onboarding-tickets/redeem")
                .header(TenantDomainWebFilter.HEADER_X_TENANT, tenant)
                .headers(h -> {
                    if (accessToken != null) {
                        h.setBearerAuth(accessToken);
                    }
                    if (forwardedFor != null) {
                        h.set("X-Forwarded-For", forwardedFor);
                    }
                })
                .bodyValue(Map.of("ticket", ticket))
                .exchange();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> redeemed(String ticket) {
        return redeem(ticket, TEST_TENANT, null).expectStatus().isOk()
                .expectBody(Map.class).returnResult().getResponseBody();
    }

    // ------------------------------------------------------------------ ticket request

    @Test
    void requestTicket_tenantAdministratorMachine_getsAShortAddressAndCreatesNoAccount() {
        // Arrange: AC-01
        var email = email("ana");

        // Act
        var body = requestTicket(adminToken(), Map.of("email", email, "credentialOffer", OFFER))
                .expectStatus().isCreated()
                .expectBody(Map.class).returnResult().getResponseBody();

        // Assert
        var url = (String) body.get("onboardingUrl");
        assertThat(url).matches("https://" + PUBLIC_HOST.replace(".", "\\.") + "/t#[A-Za-z0-9_-]{22}");
        assertThat(body).containsEntry("expiresIn", 300);
        var ticket = url.substring(url.indexOf('#') + 1);
        assertThat(ticket).hasSize(22);
        assertThat(countInTestTenant("onboarding_preregistration WHERE email = '" + email + "'")).isEqualTo(1);
        assertThat(countInTestTenant("onboarding_preregistration WHERE token_hash = '" + ticket + "'")).isZero();
        assertThat(countInTestTenant("wallet_user WHERE email = '" + email + "'")).isZero();
        assertThat(countInTestTenant("audit_log WHERE action = 'PREREGISTRATION_CREATED'"
                + " AND metadata LIKE '%portal-machine.example.org%'")).isPositive();
        assertThat(countInTestTenant("audit_log WHERE metadata LIKE '%" + email + "%'")).isZero();
    }

    @Test
    void requestTicket_withoutTheTenantAdministratorPower_isRejectedAndStoresNothing() {
        // Arrange: AC-02
        var email = email("rejected");
        var future = Instant.now().plusSeconds(60);
        var adminPower = List.of(TestSystemTokens.onboardingPower(TEST_TENANT));

        // Act + Assert
        requestTicket(null, Map.of("email", email)).expectStatus().isUnauthorized();
        requestTicket(VERIFIER_KEYS.token(ISSUER, TEST_TENANT, "LEARCredentialEmployee", adminPower, future),
                Map.of("email", email)).expectStatus().isForbidden()
                .expectBody().jsonPath("$.type").isEqualTo("insufficient_permission");
        requestTicket(VERIFIER_KEYS.token(ISSUER, TEST_TENANT, "LEARCredentialMachine",
                        List.of(Map.of("type", "Domain", "domain", TEST_TENANT, "function", "ProductOffering",
                                "action", List.of("Create"))), future),
                Map.of("email", email)).expectStatus().isForbidden();
        // AD-9: the tenant's Onboarding · Execute with type domain is an organization administrator
        requestTicket(VERIFIER_KEYS.token(ISSUER, TEST_TENANT, "LEARCredentialMachine",
                        List.of(Map.of("type", "domain", "domain", TEST_TENANT, "function", "Onboarding",
                                "action", List.of("Execute"))), future),
                Map.of("email", email)).expectStatus().isForbidden()
                .expectBody().jsonPath("$.type").isEqualTo("insufficient_permission");
        requestTicket(VERIFIER_KEYS.token(ISSUER, TEST_TENANT, "LEARCredentialMachine",
                        List.of(TestSystemTokens.onboardingPower("kpmg")), future),
                Map.of("email", email)).expectStatus().isForbidden();
        requestTicket(VERIFIER_KEYS.token(ISSUER, "kpmg", "LEARCredentialMachine", adminPower, future),
                Map.of("email", email)).expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.type").isEqualTo("invalid_token");
        assertThat(countInTestTenant("onboarding_preregistration WHERE email = '" + email + "'")).isZero();
    }

    @Test
    void requestTicket_tenantWithoutOnboardingTickets_isOnboardingDisabled() {
        // Arrange: AC-02, a tenant that does not enable onboarding tickets
        var token = VERIFIER_KEYS.token("https://" + DISABLED_TENANT + ".eudistack.test/verifier", DISABLED_TENANT,
                "LEARCredentialMachine", List.of(TestSystemTokens.onboardingPower(DISABLED_TENANT)),
                Instant.now().plusSeconds(60));

        // Act + Assert
        webClient.post().uri("/api/v1/onboarding-tickets")
                .header(TenantDomainWebFilter.HEADER_X_TENANT, DISABLED_TENANT)
                .header("X-Forwarded-Proto", "https")
                .header("X-Forwarded-Host", DISABLED_TENANT + ".eudistack.test")
                .headers(h -> h.setBearerAuth(token))
                .bodyValue(Map.of("email", email("disabled")))
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.type").isEqualTo("onboarding_disabled");
    }

    // ------------------------------------------------------------------ redemption

    @Test
    void redeem_emailWithoutAccount_givesTheRegistrationTicketAndTheOfferWithoutCreatingTheAccount() {
        // Arrange
        var email = email("new");
        var ticket = ticketFor(email);

        // Act
        var body = redeemed(ticket);

        // Assert
        assertThat(body).containsEntry("hasPasskeys", false).containsEntry("sessionOfAccount", false)
                .containsEntry("credentialOffer", OFFER).containsKey("registrationTicket")
                .containsEntry("expiresIn", 300);
        assertThat(countInTestTenant("wallet_user WHERE email = '" + email + "'")).isZero();
        assertThat(countInTestTenant("onboarding_preregistration WHERE email = '" + email + "'"
                + " AND webauthn_user_handle IS NOT NULL AND redeemed_at IS NOT NULL")).isEqualTo(1);
    }

    @Test
    void redeem_sameTicketTwice_isInvalidTheSecondTime() {
        // Arrange: AC-06
        var ticket = ticketFor(email("twice"));
        redeemed(ticket);

        // Act + Assert
        redeem(ticket, TEST_TENANT, null).expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.type").isEqualTo("invalid_ticket");
        assertThat(countInTestTenant("audit_log WHERE action = 'ONBOARDING_TICKET_REJECTED'")).isPositive();
    }

    @Test
    void redeem_twoConcurrentRedemptions_onlyOneSucceeds() {
        // Arrange: AC-07
        var ticket = ticketFor(email("concurrent"));
        var statuses = new ArrayList<CompletableFuture<HttpStatus>>();

        // Act
        for (int i = 0; i < 2; i++) {
            statuses.add(CompletableFuture.supplyAsync(() -> HttpStatus.valueOf(
                    redeem(ticket, TEST_TENANT, null).returnResult(Void.class).getStatus().value())));
        }
        var results = statuses.stream().map(CompletableFuture::join).toList();

        // Assert
        assertThat(results).containsExactlyInAnyOrder(HttpStatus.OK, HttpStatus.UNAUTHORIZED);
    }

    @Test
    void redeem_accountWithPasskeys_givesNoRegistrationTicketAndDeletesThePreregistration() {
        // Arrange: AC-08
        var email = email("existing");
        authClient().signUp(email, new SoftwareAuthenticator(TEST_ORIGIN));
        var ticket = ticketFor(email);

        // Act
        var body = redeemed(ticket);

        // Assert
        assertThat(body).containsEntry("hasPasskeys", true).containsEntry("credentialOffer", OFFER)
                .doesNotContainKey("registrationTicket");
        assertThat(countInTestTenant("onboarding_preregistration WHERE email = '" + email + "'")).isZero();
    }

    @Test
    void redeem_withASessionOfTheTicketAccount_saysSo() {
        // Arrange: AC-09
        var email = email("session");
        var session = authClient().signUp(email, new SoftwareAuthenticator(TEST_ORIGIN));
        var ticket = ticketFor(email);

        // Act + Assert
        redeem(ticket, TEST_TENANT, session.accessToken()).expectStatus().isOk().expectBody()
                .jsonPath("$.sessionOfAccount").isEqualTo(true)
                .jsonPath("$.registrationTicket").doesNotExist()
                .jsonPath("$.credentialOffer").isEqualTo(OFFER);
    }

    @Test
    void redeem_ticketOfAnotherTenant_isInvalidAndLeavesItIntact() {
        // Arrange: AC-12
        var email = email("othertenant");
        var ticket = ticketFor(email);

        // Act + Assert
        redeem(ticket, RESTRICTED_TENANT, null).expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.type").isEqualTo("invalid_ticket");
        assertThat(countInTestTenant("onboarding_preregistration WHERE email = '" + email + "'"
                + " AND redeemed_at IS NULL")).isEqualTo(1);
    }

    @Test
    void redeem_overTheLimitPerIp_isRateLimited() {
        // Arrange: ES-07, 10 per origin and window
        var unknownTicket = "AAAAAAAAAAAAAAAAAAAAAA";
        var forwardedFor = "198.51.100.1, 203.0.113.60, 10.0.0.9";
        for (int i = 0; i < 10; i++) {
            redeem(unknownTicket, TEST_TENANT, null, forwardedFor).expectStatus().isUnauthorized();
        }

        // Act + Assert
        redeem(unknownTicket, TEST_TENANT, null, forwardedFor).expectStatus().isEqualTo(HttpStatus.TOO_MANY_REQUESTS)
                .expectHeader().exists("Retry-After")
                .expectBody().jsonPath("$.type").isEqualTo("rate_limited");
    }

    // ------------------------------------------------------------------ restricted mode

    @Test
    void verifyEmail_restrictedModeEmailWithoutAccount_createsNothingAndAnswersNoAccount() {
        // Arrange: AC-13
        setupEmailCapture();
        var email = email("restricted");
        var client = new WalletAuthClient(webClient, capturedOtps,
                h -> h.set(TenantDomainWebFilter.HEADER_X_TENANT, RESTRICTED_TENANT),
                "https://" + RESTRICTED_TENANT + ".eudistack.test");
        client.requestCode(email).expectStatus().isAccepted();

        // Act + Assert
        client.verifyCode(email, capturedOtps.get(email)).expectStatus().isForbidden().expectBody()
                .jsonPath("$.type").isEqualTo("no_account")
                .jsonPath("$.signupUrl").isEqualTo(SIGNUP_URL);
        assertThat(count(RESTRICTED_SCHEMA, "wallet_user WHERE email = '" + email + "'")).isZero();
        assertThat(count(RESTRICTED_SCHEMA, "audit_log WHERE action = 'ONBOARDING_WITHOUT_TICKET_REJECTED'"))
                .isPositive();
        // AC-19: the trace never carries the email
        assertThat(count(RESTRICTED_SCHEMA, "audit_log WHERE metadata LIKE '%" + email + "%'")).isZero();
    }

    @Test
    void requestCode_restrictedMode_answersTheSameWithAndWithoutAccount() {
        // Arrange: AC-16, an account created with a ticket and an email without account
        captureNotices();
        setupEmailCapture();
        var client = new WalletAuthClient(webClient, capturedOtps,
                h -> h.set(TenantDomainWebFilter.HEADER_X_TENANT, RESTRICTED_TENANT), RESTRICTED_ORIGIN);
        var withAccount = email("restrictedwith");
        client.registerPasskey(registrationTicketOf(ticketFor(withAccount, RESTRICTED_TENANT), RESTRICTED_TENANT),
                new SoftwareAuthenticator(RESTRICTED_ORIGIN));
        var withoutAccount = email("restrictedwithout");

        // Act
        var answerWith = client.requestCode(withAccount).expectStatus().isAccepted()
                .expectBody(String.class).returnResult().getResponseBody();
        var answerWithout = client.requestCode(withoutAccount).expectStatus().isAccepted()
                .expectBody(String.class).returnResult().getResponseBody();

        // Assert: same status and body, and the code goes out in both cases
        assertThat(answerWith).isEqualTo(answerWithout);
        assertThat(capturedOtps).containsKeys(withAccount, withoutAccount);
    }

    // ------------------------------------------------------------------ "it was not me"

    private static String sha256(String raw) {
        try {
            return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                    .digest(raw.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * An account created with a ticket and the "it was not me" token of its new-account email. Until
     * task 6 creates it, the token row is inserted here as the registration will store it.
     */
    private String disavowalTokenFor(String email, String expiresAt) {
        authClient().signUp(email, new SoftwareAuthenticator(TEST_ORIGIN));
        var token = "nm" + System.nanoTime() + "abcdefghijklmnopqrstuvwxyz";
        var schema = TEST_TENANT + "_business_wallet";
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            var inserted = conn.createStatement().executeUpdate("INSERT INTO " + schema + ".onboarding_disavowal"
                    + " (id, token_hash, user_id, passkey_id, requested_by, registered_at, account_created, expires_at)"
                    + " SELECT gen_random_uuid(), '" + sha256(token) + "', u.id, p.id, 'portal-machine.example.org',"
                    + " now(), true, " + expiresAt + " FROM " + schema + ".wallet_user u JOIN " + schema + ".user_passkey p"
                    + " ON p.user_id = u.id WHERE u.email = '" + email + "'");
            assertThat(inserted).isEqualTo(1);
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        return token;
    }

    private WebTestClient.ResponseSpec disavow(String token) {
        return webClient.post().uri("/api/v1/auth/onboarding-tickets/disavowals")
                .bodyValue(Map.of("token", token)).exchange();
    }

    @Test
    void disavow_endsTheSessionsRemovesThePasskeyAndAlertsTheSecurityContact() {
        // Arrange: AC-10
        var email = email("notme");
        var token = disavowalTokenFor(email, "now() + interval '7 days'");
        when(emailSender.sendOnboardingAlert(anyString(), any(), any())).thenReturn(Mono.empty());

        // Act
        disavow(token).expectStatus().isNoContent();

        // Assert
        var user = "(SELECT id FROM " + TEST_TENANT + "_business_wallet.wallet_user WHERE email = '" + email + "')";
        assertThat(countInTestTenant("user_passkey WHERE user_id = " + user)).isZero();
        assertThat(countInTestTenant("refresh_token WHERE user_id = " + user + " AND revoked = false")).isZero();
        assertThat(countInTestTenant("wallet_user WHERE email = '" + email + "'")).isEqualTo(1);
        assertThat(countInTestTenant("audit_log WHERE action = 'ONBOARDING_DISAVOWED' AND actor_id = " + user))
                .isEqualTo(1);
        verify(emailSender).sendOnboardingAlert(eq(SECURITY_CONTACT),
                argThat(alert -> alert.maskedEmail().startsWith("n***@") && !alert.maskedEmail().contains("notme")),
                any());

        // A second time, the link is no longer valid
        disavow(token).expectStatus().isUnauthorized().expectBody().jsonPath("$.type").isEqualTo("invalid_token");
    }

    @Test
    void disavow_tokenOlderThanSevenDays_isInvalidAndChangesNothing() {
        // Arrange: AC-10
        var email = email("notmelate");
        var token = disavowalTokenFor(email, "now() - interval '1 minute'");

        // Act + Assert
        disavow(token).expectStatus().isUnauthorized();
        assertThat(countInTestTenant("user_passkey WHERE user_id = (SELECT id FROM " + TEST_TENANT
                + "_business_wallet.wallet_user WHERE email = '" + email + "')")).isEqualTo(1);
    }

    // ------------------------------------------------------------------ passkey registration with a ticket

    /** Ticket of {@code tenant} for {@code email}, requested by its administrator machine. */
    private String ticketFor(String email, String tenant) {
        var host = tenant + ".eudistack.test";
        var token = VERIFIER_KEYS.token("https://" + host + "/verifier", tenant, "LEARCredentialMachine",
                List.of(TestSystemTokens.onboardingPower(tenant)), Instant.now().plusSeconds(60));
        var url = (String) webClient.post().uri("/api/v1/onboarding-tickets")
                .header(TenantDomainWebFilter.HEADER_X_TENANT, tenant)
                .header("X-Forwarded-Proto", "https")
                .header("X-Forwarded-Host", host)
                .headers(h -> h.setBearerAuth(token))
                .bodyValue(Map.of("email", email, "credentialOffer", OFFER))
                .exchange()
                .expectStatus().isCreated()
                .expectBody(Map.class).returnResult().getResponseBody().get("onboardingUrl");
        return url.substring(url.indexOf('#') + 1);
    }

    @SuppressWarnings("unchecked")
    private String registrationTicketOf(String ticket, String tenant) {
        var body = redeem(ticket, tenant, null).expectStatus().isOk()
                .expectBody(Map.class).returnResult().getResponseBody();
        return (String) body.get("registrationTicket");
    }

    /** Captures the new-account emails sent by the service. */
    private List<AccountCreatedNotice> captureNotices() {
        var notices = new CopyOnWriteArrayList<AccountCreatedNotice>();
        doAnswer(invocation -> {
            notices.add(invocation.getArgument(1));
            return Mono.empty();
        }).when(emailSender).sendAccountCreatedNotice(anyString(), any(), any());
        when(emailSender.sendOnboardingAlert(anyString(), any(), any())).thenReturn(Mono.empty());
        return notices;
    }

    /** Captures the alerts to the security contact; call after {@link #captureNotices()}, which stubs them. */
    private List<OnboardingAlert> captureAlerts() {
        var alerts = new CopyOnWriteArrayList<OnboardingAlert>();
        doAnswer(invocation -> {
            alerts.add(invocation.getArgument(1));
            return Mono.empty();
        }).when(emailSender).sendOnboardingAlert(anyString(), any(), any());
        return alerts;
    }

    /** An account of the test tenant that never registered a passkey, like an email sign-up left half way. */
    private static void accountWithoutPasskeys(String email) {
        sql("INSERT INTO wallet_user (id, email) VALUES ('" + UUID.randomUUID() + "', '" + email + "')");
    }

    private static String tokenOf(AccountCreatedNotice notice) {
        return notice.disavowalUrl().substring(notice.disavowalUrl().indexOf('#') + 1);
    }

    @Test
    void onboarding_accountWithoutPasskeys_isRecognizedAndGetsTheAddedNoticeThatTheItWasNotMeLinkAnswers() {
        // Arrange: EC-01 and P17, the account exists without passkeys: no new account, but the same warning
        var notices = captureNotices();
        var alerts = captureAlerts();
        var email = email("recognized");
        accountWithoutPasskeys(email);
        var registrationTicket = registrationTicketOf(ticketFor(email, TEST_TENANT), TEST_TENANT);

        // Act
        var session = authClient().registerPasskey(registrationTicket, new SoftwareAuthenticator(TEST_ORIGIN));

        // Assert: the account is the same, the passkey is its first one, and the row and the email say "not created"
        assertThat(session.accessToken()).isNotBlank();
        assertThat(countInTestTenant("wallet_user WHERE email = '" + email + "'")).isEqualTo(1);
        assertThat(countInTestTenant("user_passkey WHERE user_id = " + userOf(email))).isEqualTo(1);
        assertThat(countInTestTenant("onboarding_disavowal WHERE user_id = " + userOf(email)
                + " AND account_created = false AND token_hash IS NOT NULL")).isEqualTo(1);
        assertThat(notices).hasSize(1);
        assertThat(notices.get(0).accountCreated()).isFalse();

        // And "it was not me" removes that passkey and alerts the security contact with the "added" variant
        disavow(tokenOf(notices.get(0))).expectStatus().isNoContent();
        assertThat(countInTestTenant("user_passkey WHERE user_id = " + userOf(email))).isZero();
        assertThat(alerts).hasSize(1);
        assertThat(alerts.get(0).accountCreated()).isFalse();
    }

    @Test
    @SuppressWarnings("unchecked")
    void onboarding_userAgentOfTheRegistration_isTheDeviceOfTheNoticeNotTheNameOfTheClient() {
        // Arrange: EC-16, P19 - the client sends the name "Test device"; the notice shows what the service derives
        var notices = captureNotices();
        var email = email("devicelabel");
        var client = authClient();
        var registrationTicket = registrationTicketOf(ticketFor(email, TEST_TENANT), TEST_TENANT);
        var options = client.registrationOptions(registrationTicket);
        var credential = new SoftwareAuthenticator(TEST_ORIGIN).register((Map<String, Object>) options.get("publicKey"));

        // Act
        client.registerSpec(registrationTicket, options.get("ceremonyId"), credential, true, null,
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
                        + "Version/17.5 Mobile/15E148 Safari/604.1")
                .expectStatus().isCreated();

        // Assert
        assertThat(notices).hasSize(1);
        assertThat(notices.get(0).deviceName()).isEqualTo("iPhone · Safari");
    }

    @Test
    void onboarding_secondTicketAfterADisavowal_sendsANewNoticeWithANewLink() {
        // Arrange: EC-01, the account is left without passkeys by the first "it was not me"
        var notices = captureNotices();
        var email = email("again");
        authClient().registerPasskey(registrationTicketOf(ticketFor(email, TEST_TENANT), TEST_TENANT),
                new SoftwareAuthenticator(TEST_ORIGIN));
        disavow(tokenOf(notices.get(0))).expectStatus().isNoContent();
        assertThat(countInTestTenant("user_passkey WHERE user_id = " + userOf(email))).isZero();

        // Act
        authClient().registerPasskey(registrationTicketOf(ticketFor(email, TEST_TENANT), TEST_TENANT),
                new SoftwareAuthenticator(TEST_ORIGIN));

        // Assert: a second notice for the account that already existed, with its own link that works
        assertThat(notices).hasSize(2);
        assertThat(notices.get(0).accountCreated()).isTrue();
        assertThat(notices.get(1).accountCreated()).isFalse();
        assertThat(tokenOf(notices.get(1))).isNotEqualTo(tokenOf(notices.get(0)));
        assertThat(countInTestTenant("wallet_user WHERE email = '" + email + "'")).isEqualTo(1);
        disavow(tokenOf(notices.get(1))).expectStatus().isNoContent();
        assertThat(countInTestTenant("user_passkey WHERE user_id = " + userOf(email))).isZero();
    }

    private static String userOf(String email) {
        return "(SELECT id FROM " + TEST_TENANT + "_business_wallet.wallet_user WHERE email = '" + email + "')";
    }

    @Test
    void onboarding_emailWithoutAccount_createsTheAccountWithThePasskeyAndTheItWasNotMeLinkWorks() {
        // Arrange: AC-03, then AC-10 with the link of the real email
        var notices = captureNotices();
        var email = email("fullonboarding");
        var registrationTicket = registrationTicketOf(ticketFor(email, TEST_TENANT), TEST_TENANT);
        var authenticator = new SoftwareAuthenticator(TEST_ORIGIN);

        // Act
        var session = authClient().registerPasskey(registrationTicket, authenticator);

        // Assert: account, passkey marked with the pre-registration, pre-registration gone, session open
        assertThat(session.accessToken()).isNotBlank();
        assertThat(countInTestTenant("user_passkey WHERE user_id = " + userOf(email)
                + " AND onboarding_preregistration_id IS NOT NULL")).isEqualTo(1);
        assertThat(countInTestTenant("onboarding_preregistration WHERE email = '" + email + "'")).isZero();
        assertThat(countInTestTenant("onboarding_disavowal WHERE user_id = " + userOf(email)
                + " AND token_hash IS NOT NULL")).isEqualTo(1);
        // The passkey carries the user handle of the account: a later sign-in works (decision P2)
        assertThat(authClient().signIn(authenticator).accessToken()).isNotBlank();
        // The new-account email went out with the "it was not me" link (provisional, P5)
        assertThat(notices).hasSize(1);
        var link = notices.get(0).disavowalUrl();
        assertThat(link).startsWith("https://" + PUBLIC_HOST + "/no-he-sido-yo#");

        // And the link works
        disavow(link.substring(link.indexOf('#') + 1)).expectStatus().isNoContent();
        assertThat(countInTestTenant("user_passkey WHERE user_id = " + userOf(email))).isZero();
    }

    @Test
    void onboarding_restrictedTenant_createsTheAccountWithTheTicket() {
        // Arrange: AC-17, the only way to create an account in restricted mode
        captureNotices();
        var email = email("restrictedonboarding");
        var registrationTicket = registrationTicketOf(ticketFor(email, RESTRICTED_TENANT), RESTRICTED_TENANT);
        var client = new WalletAuthClient(webClient, capturedOtps,
                h -> h.set(TenantDomainWebFilter.HEADER_X_TENANT, RESTRICTED_TENANT), RESTRICTED_ORIGIN);

        // Act
        var session = client.registerPasskey(registrationTicket, new SoftwareAuthenticator(RESTRICTED_ORIGIN));

        // Assert
        assertThat(session.accessToken()).isNotBlank();
        assertThat(count(RESTRICTED_SCHEMA, "wallet_user WHERE email = '" + email + "'")).isEqualTo(1);
    }

    @Test
    void onboarding_accountOfTheEmailAppearedAfterTheRedemption_isRejected() {
        // Arrange: EC-04 (decision P7), the account is created by email between the redemption and the passkey
        var email = email("appeared");
        var registrationTicket = registrationTicketOf(ticketFor(email, TEST_TENANT), TEST_TENANT);
        authClient().signUp(email, new SoftwareAuthenticator(TEST_ORIGIN));

        // Act + Assert
        authClient().registerPasskeySpec(registrationTicket, new SoftwareAuthenticator(TEST_ORIGIN), null)
                .expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.type").isEqualTo("invalid_ticket");
        assertThat(countInTestTenant("onboarding_preregistration WHERE email = '" + email + "'")).isZero();
        assertThat(countInTestTenant("user_passkey WHERE user_id = " + userOf(email))).isEqualTo(1);
    }

    @Test
    @SuppressWarnings("unchecked")
    void onboarding_ceremonyOfAnotherPreregistration_isRejected() {
        // Arrange: EC-13 (decision P9), two tickets of emails without account
        var client = authClient();
        var first = registrationTicketOf(ticketFor(email("ceremonya"), TEST_TENANT), TEST_TENANT);
        var second = registrationTicketOf(ticketFor(email("ceremonyb"), TEST_TENANT), TEST_TENANT);
        var options = client.registrationOptions(first);
        var credential = new SoftwareAuthenticator(TEST_ORIGIN).register((Map<String, Object>) options.get("publicKey"));

        // Act + Assert
        client.registerSpec(second, options.get("ceremonyId"), credential, true, null)
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.type").isEqualTo("registration_failed");
    }

    @Test
    @SuppressWarnings("unchecked")
    void onboarding_twoConcurrentRegistrationsOfTheSameEmail_onlyOneRegistersThePasskey() {
        // Arrange: EC-04, two tickets of the same email without account, both redeemed
        captureNotices();
        var email = email("concurrentreg");
        var client = authClient();
        var registrations = new ArrayList<Supplier<HttpStatus>>();
        for (int i = 0; i < 2; i++) {
            var registrationTicket = registrationTicketOf(ticketFor(email, TEST_TENANT), TEST_TENANT);
            var options = client.registrationOptions(registrationTicket);
            var credential = new SoftwareAuthenticator(TEST_ORIGIN).register((Map<String, Object>) options.get("publicKey"));
            registrations.add(() -> HttpStatus.valueOf(client.registerSpec(registrationTicket, options.get("ceremonyId"),
                    credential, true, null).returnResult(Void.class).getStatus().value()));
        }

        // Act
        var running = registrations.stream().map(CompletableFuture::supplyAsync).toList();
        var results = running.stream().map(CompletableFuture::join).toList();

        // Assert: one account with one passkey
        assertThat(results).containsExactlyInAnyOrder(HttpStatus.CREATED, HttpStatus.UNAUTHORIZED);
        assertThat(countInTestTenant("wallet_user WHERE email = '" + email + "'")).isEqualTo(1);
        assertThat(countInTestTenant("user_passkey WHERE user_id = " + userOf(email))).isEqualTo(1);
    }

    @Test
    @SuppressWarnings("unchecked")
    void onboarding_passkeyCustodyWithoutPrf_createsNothingAndAnotherAuthenticatorCanRetry() {
        // Arrange: EC-11, a ticket of an email without account in a tenant with passkey custody
        captureNotices();
        var email = email("noprf");
        var client = authClient();
        var registrationTicket = registrationTicketOf(ticketFor(email, TEST_TENANT), TEST_TENANT);

        PasskeyRegistrationIT.withPasskeyCustody(() -> {
            // Act: an authenticator without PRF
            var options = client.registrationOptions(registrationTicket);
            var credential = new SoftwareAuthenticator(TEST_ORIGIN).withPrfEnabled(false)
                    .register((Map<String, Object>) options.get("publicKey"));
            client.registerSpec(registrationTicket, options.get("ceremonyId"), credential, false, null)
                    .expectStatus().isEqualTo(422)
                    .expectBody().jsonPath("$.type").isEqualTo("passkey_prf_unsupported");

            // Assert: no account nor passkey, and the same registration ticket still works with another one
            assertThat(countInTestTenant("wallet_user WHERE email = '" + email + "'")).isZero();
            client.registerPasskeySpec(registrationTicket, new SoftwareAuthenticator(TEST_ORIGIN), null)
                    .expectStatus().isCreated();
        });
        assertThat(countInTestTenant("user_passkey WHERE user_id = " + userOf(email))).isEqualTo(1);
    }

    @Test
    void onboarding_mailUnavailable_completesTheOnboardingAndTracesTheFailure() {
        // Arrange: ES-06, the new-account email cannot be sent
        when(emailSender.sendAccountCreatedNotice(anyString(), any(), any()))
                .thenReturn(Mono.error(new IllegalStateException("smtp down")));
        var email = email("noticedown");
        var registrationTicket = registrationTicketOf(ticketFor(email, TEST_TENANT), TEST_TENANT);

        // Act
        var session = authClient().registerPasskey(registrationTicket, new SoftwareAuthenticator(TEST_ORIGIN));

        // Assert: the onboarding and its session stand
        assertThat(session.accessToken()).isNotBlank();
        assertThat(countInTestTenant("user_passkey WHERE user_id = " + userOf(email))).isEqualTo(1);
        assertThat(countInTestTenant("audit_log WHERE action = 'ONBOARDING_NOTICE_FAILED' AND actor_id = "
                + userOf(email))).isEqualTo(1);
    }

    @Test
    void disavow_mailUnavailable_stillEndsTheSessionsAndRemovesThePasskey() {
        // Arrange: ES-06, the alert to the security contact cannot be sent
        var email = email("alertdown");
        var token = disavowalTokenFor(email, "now() + interval '7 days'");
        when(emailSender.sendOnboardingAlert(anyString(), any(), any()))
                .thenReturn(Mono.error(new IllegalStateException("smtp down")));

        // Act
        disavow(token).expectStatus().isNoContent();

        // Assert
        var user = userOf(email);
        assertThat(countInTestTenant("user_passkey WHERE user_id = " + user)).isZero();
        assertThat(countInTestTenant("refresh_token WHERE user_id = " + user + " AND revoked = false")).isZero();
        assertThat(countInTestTenant("audit_log WHERE action = 'ONBOARDING_DISAVOWED' AND actor_id = " + user))
                .isEqualTo(1);
        assertThat(countInTestTenant("audit_log WHERE action = 'ONBOARDING_ALERT_FAILED' AND actor_id = " + user))
                .isEqualTo(1);
    }

    @Test
    void auditTrail_ofAWholeOnboarding_hasItsEventsWithoutSecretsNorTheEmail() {
        // Arrange: AC-19, from the ticket to "it was not me", with a rejected redemption on the way
        var since = query("SELECT now() AS t").get(0).get("t");
        var notices = captureNotices();
        var email = email("trail");
        var ticket = ticketFor(email, TEST_TENANT);
        redeem("A".repeat(22), TEST_TENANT, null).expectStatus().isUnauthorized();
        var registrationTicket = registrationTicketOf(ticket, TEST_TENANT);
        var authenticator = new SoftwareAuthenticator(TEST_ORIGIN);
        authClient().registerPasskey(registrationTicket, authenticator);
        var link = notices.get(0).disavowalUrl();
        var disavowalToken = link.substring(link.indexOf('#') + 1);

        // Act
        disavow(disavowalToken).expectStatus().isNoContent();

        // Assert: the events of the trail
        var ofThisRun = "audit_log WHERE created_at >= '" + since + "'";
        for (var event : List.of("PREREGISTRATION_CREATED", "ONBOARDING_TICKET_REJECTED", "ONBOARDING_TICKET_REDEEMED",
                "ACCOUNT_CREATED", "PASSKEY_REGISTERED", "ONBOARDING_NOTICE_SENT", "ONBOARDING_DISAVOWED")) {
            assertThat(countInTestTenant(ofThisRun + " AND action = '" + event + "'")).as(event).isPositive();
        }
        // and none carries the email, a ticket, the token or the passkey beyond its identifier
        for (var secret : List.of(email, ticket, registrationTicket, disavowalToken,
                authenticator.credentialIdBase64Url())) {
            assertThat(countInTestTenant(ofThisRun + " AND metadata LIKE '%" + secret + "%'")).isZero();
        }
    }

    @Test
    void systemToken_atAnEndpointThatRequiresASession_isUnauthorized() {
        // Arrange: ES-05, a valid system token of a tenant administrator machine
        var systemToken = adminToken();

        // Act + Assert: the session filter does not accept it
        webClient.get().uri("/api/v1/auth/passkeys")
                .header(TenantDomainWebFilter.HEADER_X_TENANT, TEST_TENANT)
                .header("X-Forwarded-Proto", "https")
                .header("X-Forwarded-Host", PUBLIC_HOST)
                .headers(h -> h.setBearerAuth(systemToken))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void signIn_withTheRegistrationTicketOfAPreregistrationWithoutAccount_isInvalidTicket() {
        // Arrange: EC-07, the ticket of an email without account only registers the first passkey
        var registrationTicket = registrationTicketOf(ticketFor(email("signin"), TEST_TENANT), TEST_TENANT);

        // Act + Assert: a 401, never a server error
        webClient.post().uri("/api/v1/auth/sessions/options")
                .header(TenantDomainWebFilter.HEADER_X_TENANT, TEST_TENANT)
                .headers(h -> h.setBearerAuth(registrationTicket))
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.type").isEqualTo("invalid_ticket");
    }

    @Test
    void cleanup_expiredPreregistration_isDeletedWithItsTraceInTheTenantSchema() {
        // Arrange: AC-05, NFR-5, an expired pre-registration with its email
        var id = UUID.randomUUID();
        var email = email("expired");
        sql("INSERT INTO onboarding_preregistration (id, token_hash, email, requested_by, expires_at)"
                + " VALUES ('" + id + "', '" + id.toString().replace("-", "") + "', '" + email + "',"
                + " 'portal-machine.example.org', now() - interval '1 minute')");

        // Act: the hourly cleanup step, in one transaction in the tenant schema
        expireOnboardingWorkflow.expire()
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TEST_TENANT))
                .block();

        // Assert
        assertThat(countInTestTenant("onboarding_preregistration WHERE id = '" + id + "'")).isZero();
        assertThat(countInTestTenant("audit_log WHERE entity_id = '" + id + "'"
                + " AND action = 'PREREGISTRATION_EXPIRED'")).isEqualTo(1);
        assertThat(countInTestTenant("audit_log WHERE metadata LIKE '%" + email + "%'")).isZero();
    }
}
