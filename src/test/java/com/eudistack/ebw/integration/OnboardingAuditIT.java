package com.eudistack.ebw.integration;

import com.eudistack.ebw.support.SoftwareAuthenticator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * FR-22 (EUD-8 prd §3.7): registration and access leave their audit events, with the account and
 * the passkey, never the email, the code, the challenge or the authenticator response.
 */
class OnboardingAuditIT extends IntegrationTestBase {

    @BeforeEach
    void setUp() {
        setupEmailCapture();
        capturedOtps.clear();
    }

    @Test
    void firstRegistration_auditsAccountCreatedPasskeyRegisteredAndAccessGranted() {
        var email = "audit-first-" + System.nanoTime() + "@example.com";

        var session = authClient().signUp(email, new SoftwareAuthenticator(TEST_ORIGIN));

        var userId = userId(email);
        assertThat(actions(userId)).contains("ACCOUNT_CREATED", "PASSKEY_REGISTERED", "ACCESS_GRANTED");
        assertThat(query("SELECT metadata FROM audit_log WHERE action = 'ACCESS_GRANTED' AND actor_id = '"
                + userId + "'")).singleElement()
                .satisfies(row -> assertThat((String) row.get("metadata")).contains(session.passkeyId()));
    }

    @Test
    void secondPasskey_auditsAccountRecognizedAndNewPasskeyNotice() {
        var email = "audit-second-" + System.nanoTime() + "@example.com";
        var auth = authClient();
        auth.signUp(email, new SoftwareAuthenticator(TEST_ORIGIN));

        auth.signUp(email, new SoftwareAuthenticator(TEST_ORIGIN));

        assertThat(actions(userId(email))).contains("ACCOUNT_RECOGNIZED", "NEW_PASSKEY_NOTICE_SENT");
    }

    @Test
    void auditTrail_neverContainsTheEmailNorTheCode() {
        var email = "audit-private-" + System.nanoTime() + "@example.com";
        authClient().signUp(email, new SoftwareAuthenticator(TEST_ORIGIN));
        var code = capturedOtps.get(email);

        var leaking = query("SELECT action FROM audit_log WHERE metadata LIKE '%" + email + "%' OR metadata LIKE '%"
                + code + "%'");

        assertThat(leaking).isEmpty();
    }

    @Test
    void codeRequestAndRejection_areAuditedWithoutAccount() {
        var email = "audit-rejected-" + System.nanoTime() + "@example.com";
        var auth = authClient();
        auth.requestCode(email).expectStatus().isAccepted();

        auth.verifyCode(email, wrongCode(capturedOtps.get(email))).expectStatus().isUnauthorized();

        assertThat(query("SELECT actor_id FROM audit_log WHERE action = 'EMAIL_CODE_REJECTED' "
                + "ORDER BY created_at DESC LIMIT 1")).singleElement()
                .satisfies(row -> assertThat(row.get("actor_id")).isNull());
    }

    private static String wrongCode(String code) {
        return code.equals("000000") ? "111111" : "000000";
    }

    private static Object userId(String email) {
        return query("SELECT id FROM wallet_user WHERE email = '" + email + "'").get(0).get("id");
    }

    private static java.util.List<Object> actions(Object userId) {
        return query("SELECT action FROM audit_log WHERE actor_id = '" + userId + "'").stream()
                .map((Map<String, Object> row) -> row.get("action")).toList();
    }
}
