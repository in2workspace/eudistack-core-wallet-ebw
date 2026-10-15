package com.eudistack.ebw.integration;

import com.eudistack.ebw.support.SoftwareAuthenticator;
import com.eudistack.ebw.support.WalletAuthClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * EUD-8 sign-in and session (FR-12 to FR-21): verified passkey sign-in, unknown credential,
 * anomalous use, refresh cookie with inactivity and maximum duration, reuse detection, sign-out
 * and the X-Wallet-Request header on the cookie endpoints.
 */
class PasskeySessionIT extends IntegrationTestBase {

    private WalletAuthClient auth;

    @org.springframework.beans.factory.annotation.Autowired
    private com.eudistack.ebw.domain.repository.RefreshTokenRepository refreshTokenRepository;

    @org.springframework.beans.factory.annotation.Autowired
    private com.eudistack.ebw.application.workflow.ExpireSessionsWorkflow expireSessionsWorkflow;

    @BeforeEach
    void setUp() {
        setupEmailCapture();
        capturedOtps.clear();
        auth = authClient();
    }

    private static String email(String name) {
        return name + "-" + System.nanoTime() + "@example.com";
    }

    @Test
    void signIn_discoverablePasskey_opensSessionBoundToItWithoutEmail() {
        var authenticator = new SoftwareAuthenticator(TEST_ORIGIN);
        var registered = auth.signUp(email("ses-signin"), authenticator);

        var session = auth.signIn(authenticator);

        assertThat(session.passkeyId()).isEqualTo(registered.passkeyId());
        assertThat(query("SELECT sign_count, last_used_at FROM user_passkey WHERE id = '" + session.passkeyId() + "'"))
                .singleElement().satisfies(row -> assertThat(((Number) row.get("sign_count")).longValue()).isEqualTo(1));
        webClient.get().uri("/api/v1/credentials").headers(h -> h.setBearerAuth(session.accessToken()))
                .exchange().expectStatus().isOk();
    }

    @Test
    @SuppressWarnings("unchecked")
    void signIn_withoutTicket_optionsHaveNoAllowCredentials() {
        var options = auth.authenticationOptions(null);

        var publicKey = (Map<String, Object>) options.get("publicKey");
        assertThat(publicKey).containsEntry("rpId", TEST_RP_ID).containsEntry("timeout", 60000)
                .containsEntry("userVerification", "required");
        assertThat((java.util.List<String>) publicKey.get("hints")).containsExactly("client-device");
        assertThat((java.util.List<Object>) publicKey.get("allowCredentials")).isEmpty();
    }

    @Test
    @SuppressWarnings("unchecked")
    void signIn_withTicket_allowsTheAccountPasskeysAndConsumesTheTicket() {
        var email = email("ses-ticket");
        var authenticator = new SoftwareAuthenticator(TEST_ORIGIN);
        auth.signUp(email, authenticator);
        var ticket = auth.ticket(email);
        assertThat((java.util.List<Map<String, Object>>) ((Map<String, Object>) auth.authenticationOptions(ticket)
                .get("publicKey")).get("allowCredentials")).extracting(c -> c.get("id"))
                .containsExactly(authenticator.credentialIdBase64Url());

        auth.signInSpec(authenticator, ticket, null).expectStatus().isCreated();

        auth.authenticationOptionsSpec(ticket).expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.type").isEqualTo("invalid_ticket");
    }

    @Test
    void signIn_withTicketOfAnotherAccount_isRejected() {
        var mine = new SoftwareAuthenticator(TEST_ORIGIN);
        auth.signUp(email("ses-other-a"), mine);
        var otherTicket = auth.ticket(email("ses-other-b"));

        auth.signInSpec(mine, otherTicket, null).expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.type").isEqualTo("authentication_failed");
    }

    @Test
    void signIn_unknownPasskey_returnsUnknownCredential() {
        auth.signInSpec(new SoftwareAuthenticator(TEST_ORIGIN).withUserHandle(new byte[32]), null, null)
                .expectStatus().isUnauthorized()
                .expectHeader().contentType("application/problem+json")
                .expectBody().jsonPath("$.type").isEqualTo("unknown_credential");
    }

    @Test
    void signIn_withTicketAndNoUserHandle_isAccepted() {
        // The credential is already tied to the ticket's account.
        var email = email("ses-ticket-nohandle");
        var authenticator = new SoftwareAuthenticator(TEST_ORIGIN);
        auth.signUp(email, authenticator);
        authenticator.withoutUserHandle();

        auth.signInSpec(authenticator, auth.ticket(email), null).expectStatus().isCreated();
    }

    @Test
    void signIn_discoverableWithoutUserHandle_isRejected() {
        var authenticator = new SoftwareAuthenticator(TEST_ORIGIN);
        auth.signUp(email("ses-nohandle"), authenticator);
        authenticator.withoutUserHandle();

        auth.signInSpec(authenticator, null, null).expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.type").isEqualTo("authentication_failed");
    }

    @Test
    @SuppressWarnings("unchecked")
    void openSession_withoutWalletRequestHeader_isForbidden() {
        var authenticator = new SoftwareAuthenticator(TEST_ORIGIN);
        auth.signUp(email("ses-open-csrf"), authenticator);
        var options = auth.authenticationOptions(null);
        var credential = authenticator.authenticate((Map<String, Object>) options.get("publicKey"));

        webClient.post().uri("/api/v1/auth/sessions")
                .bodyValue(Map.of("ceremonyId", options.get("ceremonyId"), "credential", credential))
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.type").isEqualTo("forbidden");
    }

    @Test
    void refresh_withTwoRefreshCookies_isInvalidSession() {
        var session = auth.signUp(email("ses-two-cookies"), new SoftwareAuthenticator(TEST_ORIGIN));

        webClient.post().uri("/api/v1/auth/refresh")
                .header(WalletAuthClient.WALLET_REQUEST, "1")
                .cookies(c -> {
                    c.add(WalletAuthClient.COOKIE, session.refreshToken());
                    c.add(WalletAuthClient.COOKIE, "planted-by-a-sibling-host");
                })
                .exchange().expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.type").isEqualTo("invalid_session");
    }

    @Test
    void signIn_userHandleOfAnotherAccount_isRejected() {
        var authenticator = new SoftwareAuthenticator(TEST_ORIGIN);
        auth.signUp(email("ses-handle"), authenticator);
        authenticator.withUserHandle(new byte[32]);

        auth.signInSpec(authenticator, null, null).expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.type").isEqualTo("authentication_failed");
    }

    @Test
    void signIn_counterGoingBackwards_isRejectedAndAudited() {
        var authenticator = new SoftwareAuthenticator(TEST_ORIGIN).withSignCount(10);
        var registered = auth.signUp(email("ses-counter"), authenticator);
        authenticator.withSignCount(2);

        auth.signInSpec(authenticator, null, null).expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.type").isEqualTo("authentication_failed");

        assertThat(query("SELECT metadata FROM audit_log WHERE action = 'ACCESS_REJECTED' AND metadata LIKE '%"
                + registered.passkeyId() + "%'")).isNotEmpty();
    }

    @Test
    void signIn_notBackupEligiblePasskeyBecomingEligible_isRejected() {
        var authenticator = new SoftwareAuthenticator(TEST_ORIGIN).withBackupEligible(false).withBackupState(false);
        auth.signUp(email("ses-be"), authenticator);
        authenticator.withBackupEligible(true);

        auth.signInSpec(authenticator, null, null).expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.type").isEqualTo("authentication_failed");
    }

    @Test
    @SuppressWarnings("unchecked")
    void signIn_ceremonyUsedTwice_secondIsRejected() {
        var authenticator = new SoftwareAuthenticator(TEST_ORIGIN);
        auth.signUp(email("ses-ceremony"), authenticator);
        var options = auth.authenticationOptions(null);
        var credential = authenticator.authenticate((Map<String, Object>) options.get("publicKey"));
        auth.openSessionSpec(null, options.get("ceremonyId"), credential, null).expectStatus().isCreated();

        auth.openSessionSpec(null, options.get("ceremonyId"), credential, null).expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.type").isEqualTo("authentication_failed");
    }

    @Test
    void refresh_validCookieWithHeader_rotatesTheToken() {
        var session = auth.signUp(email("ses-refresh"), new SoftwareAuthenticator(TEST_ORIGIN));

        var renewed = auth.refresh(session.refreshToken());

        assertThat(renewed.refreshToken()).isNotEqualTo(session.refreshToken());
        assertThat(renewed.passkeyId()).isEqualTo(session.passkeyId());
    }

    @Test
    void refresh_withoutWalletRequestHeader_isForbidden() {
        var session = auth.signUp(email("ses-csrf"), new SoftwareAuthenticator(TEST_ORIGIN));

        auth.refreshSpec(session.refreshToken(), false).expectStatus().isForbidden()
                .expectBody().jsonPath("$.type").isEqualTo("forbidden");
    }

    @Test
    void refresh_withoutCookie_isInvalidSessionAndClearsCookie() {
        auth.refreshSpec(null, true).expectStatus().isUnauthorized()
                .expectHeader().value(HttpHeaders.SET_COOKIE, c -> assertThat(c).contains("Max-Age=0"))
                .expectBody().jsonPath("$.type").isEqualTo("invalid_session");
    }

    @Test
    void refresh_reusedToken_endsTheWholeSession() {
        var session = auth.signUp(email("ses-reuse"), new SoftwareAuthenticator(TEST_ORIGIN));
        var renewed = auth.refresh(session.refreshToken());

        auth.refreshSpec(session.refreshToken(), true).expectStatus().isUnauthorized();

        auth.refreshSpec(renewed.refreshToken(), true).expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.type").isEqualTo("invalid_session");
    }

    @Test
    void refresh_afterInactivityPeriod_isRejected() {
        var session = auth.signUp(email("ses-idle"), new SoftwareAuthenticator(TEST_ORIGIN));
        sql("UPDATE refresh_token SET expires_at = now() - interval '1 second' WHERE passkey_id = '"
                + session.passkeyId() + "'");

        auth.refreshSpec(session.refreshToken(), true).expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.type").isEqualTo("invalid_session");
        assertThat(query("SELECT 1 FROM audit_log WHERE action = 'SESSION_EXPIRED' AND metadata LIKE '%idle_timeout%'"))
                .isNotEmpty();
    }

    @Test
    void refresh_pastMaximumDurationDespiteActivity_isRejected() {
        var session = auth.signUp(email("ses-max"), new SoftwareAuthenticator(TEST_ORIGIN));
        sql("UPDATE refresh_token SET session_started_at = now() - interval '9 hours' WHERE passkey_id = '"
                + session.passkeyId() + "'");

        auth.refreshSpec(session.refreshToken(), true).expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.type").isEqualTo("invalid_session");
    }

    @Test
    void endCurrentSession_thenRefresh_isRejectedAndCookieCleared() {
        var session = auth.signUp(email("ses-logout"), new SoftwareAuthenticator(TEST_ORIGIN));

        auth.endSessionSpec("current", session.accessToken(), true).expectStatus().isNoContent()
                .expectHeader().value(HttpHeaders.SET_COOKIE, c -> assertThat(c).contains("Max-Age=0"));

        auth.refreshSpec(session.refreshToken(), true).expectStatus().isUnauthorized();
    }

    @Test
    void endCurrentSession_twiceWithTheSameAccessToken_secondIsInvalidSessionAndAuditedOnce() {
        var session = auth.signUp(email("ses-logout-twice"), new SoftwareAuthenticator(TEST_ORIGIN));
        auth.endSessionSpec("current", session.accessToken(), true).expectStatus().isNoContent();

        auth.endSessionSpec("current", session.accessToken(), true).expectStatus().isUnauthorized()
                .expectHeader().value(HttpHeaders.SET_COOKIE, c -> assertThat(c).contains("Max-Age=0"))
                .expectBody().jsonPath("$.type").isEqualTo("invalid_session");

        assertThat(auditOf(sessionIdOf(session), "SESSION_ENDED")).hasSize(1);
    }

    @Test
    void endCurrentSession_withoutWalletRequestHeader_isForbidden() {
        var session = auth.signUp(email("ses-logout-csrf"), new SoftwareAuthenticator(TEST_ORIGIN));

        auth.endSessionSpec("current", session.accessToken(), false).expectStatus().isForbidden();
    }

    @Test
    void endCurrentSession_withoutSession_isInvalidSession() {
        auth.endSessionSpec("current", null, true).expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.type").isEqualTo("invalid_session");
    }

    @Test
    void endOtherSessions_keepsTheCurrentOne() {
        var authenticator = new SoftwareAuthenticator(TEST_ORIGIN);
        var first = auth.signUp(email("ses-others"), authenticator);
        var second = auth.signIn(authenticator);

        auth.endSessionSpec("others", second.accessToken(), true).expectStatus().isNoContent();

        auth.refreshSpec(first.refreshToken(), true).expectStatus().isUnauthorized();
        auth.refreshSpec(second.refreshToken(), true).expectStatus().isOk();
    }

    @Test
    void signIn_withCookieOfAnotherSession_endsThatSession() {
        // FR-21: one session per container; the new sign-in ends the session of the cookie it carries.
        var first = auth.signUp(email("ses-replace-a"), new SoftwareAuthenticator(TEST_ORIGIN));
        var other = new SoftwareAuthenticator(TEST_ORIGIN);
        auth.signUp(email("ses-replace-b"), other);

        WalletAuthClient.session(auth.signInSpec(other, null, first.refreshToken()).expectStatus().isCreated());

        auth.refreshSpec(first.refreshToken(), true).expectStatus().isUnauthorized();
    }

    @Test
    void accessToken_fromTheEmailCodeAlone_doesNotExist() {
        // FR-16 / AC-10: the code only gives a ticket, which is not a session.
        var ticket = auth.ticket(email("ses-no-session"));

        webClient.get().uri("/api/v1/credentials").headers(h -> h.setBearerAuth(ticket))
                .exchange().expectStatus().isUnauthorized();
    }

    @Test
    void housekeeping_sessionEndedMoreThanSevenDaysAgo_isDeletedAndActiveOnesKept() {
        var ended = auth.signUp(email("ses-housekeeping-old"), new SoftwareAuthenticator(TEST_ORIGIN));
        var active = auth.signUp(email("ses-housekeeping-new"), new SoftwareAuthenticator(TEST_ORIGIN));
        sql("UPDATE refresh_token SET revoked = true, expires_at = now() - interval '8 days' WHERE passkey_id = '"
                + ended.passkeyId() + "'");

        refreshTokenRepository.deleteSessionsEndedBefore(java.time.Instant.now().minus(java.time.Duration.ofDays(7)))
                .contextWrite(ctx -> ctx.put(com.eudistack.ebw.domain.model.ReactorContextKeys.TENANT_DOMAIN,
                        TEST_TENANT))
                .block();

        assertThat(query("SELECT 1 FROM refresh_token WHERE passkey_id = '" + ended.passkeyId() + "'")).isEmpty();
        assertThat(query("SELECT 1 FROM refresh_token WHERE passkey_id = '" + active.passkeyId() + "'")).isNotEmpty();
    }

    // ------------------------------------------------------------------ proactive SESSION_EXPIRED (FR-22)

    /** The housekeeping expiry step for the test tenant, as the hourly job runs it. */
    private void expireLapsedSessions() {
        expireSessionsWorkflow.expireLapsedSessions()
                .contextWrite(ctx -> ctx.put(com.eudistack.ebw.domain.model.ReactorContextKeys.TENANT_DOMAIN,
                        TEST_TENANT))
                .block();
    }

    private String sessionIdOf(WalletAuthClient.Session session) {
        return String.valueOf(query("SELECT DISTINCT session_id FROM refresh_token WHERE passkey_id = '"
                + session.passkeyId() + "'").getFirst().get("session_id"));
    }

    private java.util.List<Map<String, Object>> auditOf(String sessionId, String action) {
        return query("SELECT metadata FROM audit_log WHERE entity_id = '" + sessionId + "' AND action = '"
                + action + "'");
    }

    @Test
    void housekeeping_idleSession_isClosedAndAuditedOnceAsIdleTimeout() {
        var idle = auth.signUp(email("ses-expire-idle"), new SoftwareAuthenticator(TEST_ORIGIN));
        var active = auth.signUp(email("ses-expire-active"), new SoftwareAuthenticator(TEST_ORIGIN));
        sql("UPDATE refresh_token SET expires_at = now() - interval '1 minute' WHERE passkey_id = '"
                + idle.passkeyId() + "'");

        expireLapsedSessions();
        expireLapsedSessions();

        assertThat(auditOf(sessionIdOf(idle), "SESSION_EXPIRED")).singleElement()
                .satisfies(row -> assertThat((String) row.get("metadata")).contains("idle_timeout").doesNotContain("@"));
        assertThat(query("SELECT 1 FROM refresh_token WHERE revoked = false AND passkey_id = '"
                + idle.passkeyId() + "'")).isEmpty();
        assertThat(auditOf(sessionIdOf(active), "SESSION_EXPIRED")).isEmpty();
        auth.refreshSpec(active.refreshToken(), true).expectStatus().isOk();
    }

    @Test
    void housekeeping_twoInstancesAtOnce_auditTheSessionOnce() {
        var session = auth.signUp(email("ses-expire-concurrent"), new SoftwareAuthenticator(TEST_ORIGIN));
        sql("UPDATE refresh_token SET expires_at = now() - interval '1 minute' WHERE passkey_id = '"
                + session.passkeyId() + "'");
        var sweep = expireSessionsWorkflow.expireLapsedSessions()
                .subscribeOn(reactor.core.scheduler.Schedulers.parallel())
                .contextWrite(ctx -> ctx.put(com.eudistack.ebw.domain.model.ReactorContextKeys.TENANT_DOMAIN,
                        TEST_TENANT));

        reactor.core.publisher.Mono.zip(sweep, sweep).block();

        assertThat(auditOf(sessionIdOf(session), "SESSION_EXPIRED")).hasSize(1);
    }

    @Test
    void housekeeping_sessionAlreadyExpiredByARenewalAttempt_isNotAuditedAgain() {
        var session = auth.signUp(email("ses-expire-lazy"), new SoftwareAuthenticator(TEST_ORIGIN));
        sql("UPDATE refresh_token SET expires_at = now() - interval '1 minute' WHERE passkey_id = '"
                + session.passkeyId() + "'");
        auth.refreshSpec(session.refreshToken(), true).expectStatus().isUnauthorized();

        expireLapsedSessions();

        assertThat(auditOf(sessionIdOf(session), "SESSION_EXPIRED")).hasSize(1);
    }

    @Test
    void refresh_sessionAlreadyExpiredByHousekeeping_isInvalidSessionWithoutASecondAudit() {
        var session = auth.signUp(email("ses-expire-then-refresh"), new SoftwareAuthenticator(TEST_ORIGIN));
        sql("UPDATE refresh_token SET expires_at = now() - interval '1 minute' WHERE passkey_id = '"
                + session.passkeyId() + "'");
        expireLapsedSessions();

        auth.refreshSpec(session.refreshToken(), true).expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.type").isEqualTo("invalid_session");

        assertThat(auditOf(sessionIdOf(session), "SESSION_EXPIRED")).hasSize(1);
    }

    @Test
    void housekeeping_sessionPastItsMaximumDuration_isAuditedAsMaxDuration() {
        var session = auth.signUp(email("ses-expire-max"), new SoftwareAuthenticator(TEST_ORIGIN));
        // The last token was capped at the 8 h maximum duration, which was reached an hour ago.
        sql("UPDATE refresh_token SET session_started_at = now() - interval '9 hours', "
                + "expires_at = now() - interval '1 hour' WHERE passkey_id = '" + session.passkeyId() + "'");

        expireLapsedSessions();

        assertThat(auditOf(sessionIdOf(session), "SESSION_EXPIRED")).singleElement()
                .satisfies(row -> assertThat((String) row.get("metadata")).contains("max_duration"));
    }

    // ------------------------------------------------------------------ session check on sensitive routes

    private org.springframework.test.web.reactive.server.WebTestClient.ResponseSpec credentials(String accessToken) {
        return webClient.get().uri("/api/v1/credentials").headers(h -> h.setBearerAuth(accessToken)).exchange();
    }

    @Test
    void accessToken_afterSignOut_isRejectedOnSensitiveRoutes() {
        var session = auth.signUp(email("ses-check-logout"), new SoftwareAuthenticator(TEST_ORIGIN));
        credentials(session.accessToken()).expectStatus().isOk();

        auth.endSessionSpec("current", session.accessToken(), true).expectStatus().isNoContent();

        credentials(session.accessToken()).expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.type").isEqualTo("invalid_session");
        webClient.get().uri("/api/v1/auth/passkeys").headers(h -> h.setBearerAuth(session.accessToken()))
                .exchange().expectStatus().isUnauthorized();
    }

    @Test
    void accessToken_ofASessionEndedByCloseOthers_isRejected() {
        var authenticator = new SoftwareAuthenticator(TEST_ORIGIN);
        var other = auth.signUp(email("ses-check-others"), authenticator);
        var current = auth.signIn(authenticator);

        auth.endSessionSpec("others", current.accessToken(), true).expectStatus().isNoContent();

        credentials(other.accessToken()).expectStatus().isUnauthorized();
        credentials(current.accessToken()).expectStatus().isOk();
    }

    @Test
    void accessToken_ofASessionEndedByReuseDetection_isRejected() {
        var session = auth.signUp(email("ses-check-reuse"), new SoftwareAuthenticator(TEST_ORIGIN));
        var renewed = auth.refresh(session.refreshToken());

        auth.refreshSpec(session.refreshToken(), true).expectStatus().isUnauthorized();

        credentials(renewed.accessToken()).expectStatus().isUnauthorized();
    }

    @Test
    void accessToken_afterRenewal_keepsWorking() {
        var session = auth.signUp(email("ses-check-renewal"), new SoftwareAuthenticator(TEST_ORIGIN));

        var renewed = auth.refresh(session.refreshToken());

        credentials(session.accessToken()).expectStatus().isOk();
        credentials(renewed.accessToken()).expectStatus().isOk();
    }
}
