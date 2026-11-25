package com.eudistack.ebw.integration;

import com.eudistack.ebw.domain.model.AccountCompleteNotice;
import com.eudistack.ebw.domain.model.NewDeviceNotice;
import com.eudistack.ebw.support.SoftwareAuthenticator;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Wallet Instances end to end on a real database (EUD-15): registration after the session, binding, the session
 * check of every request ({@code instance_required}), list, rename, revocation, inactivity and isolation between
 * accounts, plus the deferred new-passkey email (EUD-8 AD-11) and the language of the account (AD-10).
 */
@Tag("integration")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@ActiveProfiles("integration")
class WalletInstanceIT extends IntegrationTestBase {

    private static final String INSTANCES = "/api/v1/wallet-instances";

    private static String email(String prefix) {
        return prefix + "-" + UUID.randomUUID() + "@example.com";
    }

    private WebTestClient.RequestHeadersSpec<?> get(String path, String token) {
        return webClient.get().uri(path).header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
    }

    private WebTestClient.ResponseSpec register(String token, String name, String type, String language) {
        return webClient.post().uri(INSTANCES)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(HttpHeaders.ACCEPT_LANGUAGE, language)
                .bodyValue(Map.of("displayName", name, "deviceType", type))
                .exchange();
    }

    private WebTestClient.ResponseSpec bind(String token, String instanceId) {
        return webClient.put().uri(INSTANCES + "/current")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .bodyValue(Map.of("instanceId", instanceId))
                .exchange();
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> list(String token) {
        return get(INSTANCES, token).exchange().expectStatus().isOk()
                .expectBodyList(Map.class).returnResult().getResponseBody().stream()
                .map(m -> (Map<String, Object>) m).toList();
    }

    private static String idOf(WebTestClient.ResponseSpec spec) {
        return (String) spec.expectBody(Map.class).returnResult().getResponseBody().get("id");
    }

    @Test
    void sessionWithoutDevice_canOnlyUseTheSessionAndDeviceRoutes() {
        // AC-07: no attestation can be obtained or presented before the device is registered
        var token = authClient().signUp(email("noinst"), new SoftwareAuthenticator(TEST_ORIGIN)).accessToken();

        get("/api/v1/credentials", token).exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.type").isEqualTo("instance_required");
        get("/api/v1/activity", token).exchange().expectStatus().isForbidden();
        get("/api/v1/auth/passkeys", token).exchange().expectStatus().isOk();
        get(INSTANCES, token).exchange().expectStatus().isOk();

        register(token, "Windows · Edge", "desktop", "es").expectStatus().isCreated();

        get("/api/v1/credentials", token).exchange().expectStatus().isOk();
    }

    @Test
    void register_newAccount_storesTheInstanceBoundToTheSessionAndConfirmsTheSignUpInItsLanguage() {
        // AC-01, AC-03, FR-08 and EUD-8 AC-32 (language of the Wallet App)
        var email = email("first");
        var token = authClient().signUp(email, new SoftwareAuthenticator(TEST_ORIGIN)).accessToken();

        var id = idOf(register(token, "  iPhone · Safari ", "mobile", "ca-ES,ca;q=0.9").expectStatus().isCreated());

        var row = query("SELECT i.display_name, i.device_type, i.status, i.registered_passkey_id, u.locale,"
                + " (SELECT count(*) FROM refresh_token t WHERE t.wallet_instance_id = i.id AND NOT t.revoked) AS bound"
                + " FROM wallet_instance i JOIN wallet_user u ON u.id = i.user_id WHERE i.id = '" + id + "'").getFirst();
        assertThat(row).containsEntry("display_name", "iPhone · Safari").containsEntry("device_type", "MOBILE")
                .containsEntry("status", "ACTIVE").containsEntry("locale", "ca");
        assertThat(row.get("registered_passkey_id")).isNotNull();
        assertThat((Long) row.get("bound")).isEqualTo(1L);
        var notice = ArgumentCaptor.forClass(AccountCompleteNotice.class);
        verify(emailSender).sendAccountCompleteNotice(eq(email), notice.capture(), eq(Locale.of("ca")));
        assertThat(notice.getValue().deviceName()).isEqualTo("iPhone · Safari");
    }

    @Test
    void register_invalidName_isRejectedAndStoresNothing() {
        // AC-02
        var token = authClient().signUp(email("bad"), new SoftwareAuthenticator(TEST_ORIGIN)).accessToken();

        register(token, "x".repeat(51), "desktop", "es").expectStatus().isBadRequest()
                .expectBody().jsonPath("$.type").isEqualTo("invalid_request");
        register(token, "Mac", "watch", "es").expectStatus().isBadRequest();
        assertThat(list(token)).isEmpty();
    }

    @Test
    void register_withoutSession_isRejected() {
        // AC-04
        webClient.post().uri(INSTANCES).bodyValue(Map.of("displayName", "Mac", "deviceType", "desktop"))
                .exchange().expectStatus().isUnauthorized();
    }

    @Test
    void secondDeviceWithANewPasskey_getsOneNewDeviceEmailThatSaysIt() {
        // EUD-8 AC-07, AD-11 and EUD-15 AC-10: one email, the new-device one with the passkey line
        var email = email("second");
        var client = authClient();
        var first = client.signUp(email, new SoftwareAuthenticator(TEST_ORIGIN)).accessToken();
        register(first, "Mac · Chrome", "desktop", "es").expectStatus().isCreated();

        var second = client.signUp(email, new SoftwareAuthenticator(TEST_ORIGIN)).accessToken();
        register(second, "Windows · Edge", "desktop", "es").expectStatus().isCreated();

        var notice = ArgumentCaptor.forClass(NewDeviceNotice.class);
        verify(emailSender).sendNewDeviceNotice(eq(email), notice.capture(), any());
        assertThat(notice.getValue().deviceName()).isEqualTo("Windows · Edge");
        assertThat(notice.getValue().passkeyAdded()).isTrue();
        verify(emailSender, never()).sendNewPasskeyNotice(anyString(), any(), any());
    }

    @Test
    void bind_rememberedDevice_bindsSilentlyAndTheListShowsItCurrentFirst() {
        // AC-05, AC-11
        var email = email("bind");
        var authenticator = new SoftwareAuthenticator(TEST_ORIGIN);
        var client = authClient();
        var first = client.signUp(email, authenticator).accessToken();
        var deviceId = idOf(register(first, "Mac · Chrome", "desktop", "es").expectStatus().isCreated());
        var other = client.signUp(email, new SoftwareAuthenticator(TEST_ORIGIN)).accessToken();
        register(other, "Windows · Edge", "desktop", "es").expectStatus().isCreated();

        var again = client.signIn(authenticator).accessToken();
        bind(again, deviceId).expectStatus().isOk().expectBody().jsonPath("$.current").isEqualTo(true);

        var devices = list(again);
        assertThat(devices).hasSize(2);
        assertThat(devices.getFirst()).containsEntry("id", deviceId).containsEntry("current", true);
        assertThat(query("SELECT count(*) AS n FROM wallet_instance i JOIN wallet_user u ON u.id = i.user_id"
                + " WHERE u.email = '" + email + "'").getFirst()).containsEntry("n", 2L);
    }

    @Test
    void bind_deviceOfAnotherAccount_isNotFound() {
        // AC-06, AC-12
        var mine = authClient().signUp(email("a"), new SoftwareAuthenticator(TEST_ORIGIN)).accessToken();
        var theirs = authClient().signUp(email("b"), new SoftwareAuthenticator(TEST_ORIGIN)).accessToken();
        var theirDevice = idOf(register(theirs, "Their phone", "mobile", "es").expectStatus().isCreated());

        bind(mine, theirDevice).expectStatus().isNotFound().expectBody().jsonPath("$.type")
                .isEqualTo("instance_not_found");
        webClient.patch().uri(INSTANCES + "/" + theirDevice).header(HttpHeaders.AUTHORIZATION, "Bearer " + mine)
                .bodyValue(Map.of("displayName", "Mine now")).exchange().expectStatus().isNotFound();
        webClient.delete().uri(INSTANCES + "/" + theirDevice).header(HttpHeaders.AUTHORIZATION, "Bearer " + mine)
                .exchange().expectStatus().isNotFound();
        assertThat(list(theirs)).extracting(d -> d.get("displayName")).containsExactly("Their phone");
    }

    @Test
    void revoke_otherDevice_endsItsSessionAndNeverReactivatesIt() {
        // AC-14, AC-16, AC-17
        var email = email("revoke");
        var client = authClient();
        var lostAuthenticator = new SoftwareAuthenticator(TEST_ORIGIN);
        var lost = client.signUp(email, lostAuthenticator).accessToken();
        var lostDevice = idOf(register(lost, "Lost phone", "mobile", "es").expectStatus().isCreated());
        var mine = client.signUp(email, new SoftwareAuthenticator(TEST_ORIGIN)).accessToken();
        register(mine, "Mac · Chrome", "desktop", "es").expectStatus().isCreated();

        webClient.delete().uri(INSTANCES + "/" + lostDevice).header(HttpHeaders.AUTHORIZATION, "Bearer " + mine)
                .exchange().expectStatus().isNoContent();

        get("/api/v1/credentials", lost).exchange().expectStatus().isUnauthorized();
        assertThat(list(mine)).extracting(d -> d.get("displayName")).containsExactly("Mac · Chrome");
        var row = query("SELECT status, revoked_by FROM wallet_instance WHERE id = '" + lostDevice + "'").getFirst();
        assertThat(row).containsEntry("status", "REVOKED").containsEntry("revoked_by", "HOLDER");
        assertThat(query("SELECT count(*) AS n FROM user_passkey p JOIN wallet_user u ON u.id = p.user_id"
                + " WHERE u.email = '" + email + "'").getFirst()).containsEntry("n", 2L);

        var back = client.signIn(lostAuthenticator).accessToken();
        bind(back, lostDevice).expectStatus().isEqualTo(410).expectBody().jsonPath("$.type")
                .isEqualTo("instance_revoked");
    }

    @Test
    void revoke_currentDevice_endsTheCallingSession() {
        // AC-15
        var token = authClient().signUp(email("self"), new SoftwareAuthenticator(TEST_ORIGIN)).accessToken();
        var device = idOf(register(token, "Mac · Chrome", "desktop", "es").expectStatus().isCreated());

        webClient.delete().uri(INSTANCES + "/" + device).header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange().expectStatus().isNoContent();

        get(INSTANCES, token).exchange().expectStatus().isUnauthorized();
    }

    @Test
    void rename_validAndInvalidNames() {
        // AC-13
        var token = authClient().signUp(email("rename"), new SoftwareAuthenticator(TEST_ORIGIN)).accessToken();
        var device = idOf(register(token, "Mac · Chrome", "desktop", "es").expectStatus().isCreated());

        webClient.patch().uri(INSTANCES + "/" + device).header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .bodyValue(Map.of("displayName", " ")).exchange().expectStatus().isBadRequest();
        webClient.patch().uri(INSTANCES + "/" + device).header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .bodyValue(Map.of("displayName", "Portátil del trabajo")).exchange().expectStatus().isOk();

        assertThat(list(token)).extracting(d -> d.get("displayName")).containsExactly("Portátil del trabajo");
    }

    @Test
    void inactivity_deviceUnusedFor90Days_isRevokedAndOneUsed89DaysAgoStays() {
        // AC-18, through the SQL of the hourly task
        var email = email("idle");
        var client = authClient();
        var stale = idOf(register(client.signUp(email, new SoftwareAuthenticator(TEST_ORIGIN)).accessToken(),
                "Old", "desktop", "es").expectStatus().isCreated());
        var recent = idOf(register(client.signUp(email, new SoftwareAuthenticator(TEST_ORIGIN)).accessToken(),
                "Recent", "desktop", "es").expectStatus().isCreated());
        sql("UPDATE wallet_instance SET last_used_at = now() - interval '90 days 1 minute' WHERE id = '" + stale + "'");
        sql("UPDATE wallet_instance SET last_used_at = now() - interval '89 days' WHERE id = '" + recent + "'");

        inactivity.revokeInactive()
                .contextWrite(ctx -> ctx.put(com.eudistack.ebw.domain.model.ReactorContextKeys.TENANT_DOMAIN, TEST_TENANT))
                .block();

        assertThat(query("SELECT status, revoked_by FROM wallet_instance WHERE id = '" + stale + "'").getFirst())
                .containsEntry("status", "REVOKED").containsEntry("revoked_by", "INACTIVITY");
        assertThat(query("SELECT status FROM wallet_instance WHERE id = '" + recent + "'").getFirst())
                .containsEntry("status", "ACTIVE");
    }

    @Test
    void trace_registrationRenameAndRevocation_carryTheInstanceAndNeverTheEmail() {
        // AC-20
        var email = email("trace");
        var token = authClient().signUp(email, new SoftwareAuthenticator(TEST_ORIGIN)).accessToken();
        var device = idOf(register(token, "Mac · Chrome", "desktop", "es").expectStatus().isCreated());
        webClient.patch().uri(INSTANCES + "/" + device).header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .bodyValue(Map.of("displayName", "Mac")).exchange().expectStatus().isOk();
        webClient.delete().uri(INSTANCES + "/" + device).header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange().expectStatus().isNoContent();

        var rows = query("SELECT action, metadata::text AS metadata FROM audit_log WHERE entity_type = 'wallet_instance'"
                + " AND entity_id = '" + device + "' ORDER BY created_at");
        assertThat(rows).extracting(r -> r.get("action")).contains("WALLET_INSTANCE_REGISTERED",
                "WALLET_INSTANCE_RENAMED", "WALLET_INSTANCE_REVOKED");
        assertThat(rows).allSatisfy(r -> assertThat(String.valueOf(r.get("metadata"))).doesNotContain(email));
    }

    @org.springframework.beans.factory.annotation.Autowired
    private com.eudistack.ebw.application.workflow.RevokeInactiveWalletInstancesWorkflow inactivity;
}
