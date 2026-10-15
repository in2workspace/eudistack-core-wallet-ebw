package com.eudistack.ebw.integration;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.keymanager.application.SessionPasskeyCredentialPort;
import com.eudistack.ebw.support.SoftwareAuthenticator;
import com.eudistack.ebw.support.WalletAuthClient;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * EUD-11 FR-13/FR-14 with passkey custody: a bound attestation is stored with the session's
 * passkey and only listed to sessions of that passkey; unbound ones are listed to every session
 * (AC-04, AC-05, AC-10, AC-11). The PRF salt lookup is limited the same way.
 */
class CredentialPasskeyCustodyIT extends IntegrationTestBase {

    @Autowired
    private SessionPasskeyCredentialPort sessionPasskeyCredentialPort;

    private WalletAuthClient auth;

    @BeforeEach
    void setUp() {
        setupEmailCapture();
        capturedOtps.clear();
        auth = authClient();
    }

    @Test
    void passkeyCustody_listsUnboundAndOnlyTheBoundOnesOfTheSessionPasskey() {
        var email = "custody-" + System.nanoTime() + "@example.com";
        var laptop = new SoftwareAuthenticator(TEST_ORIGIN);
        var phone = new SoftwareAuthenticator(TEST_ORIGIN);
        var laptopSession = auth.signUp(email, laptop);
        var phoneSession = auth.signUp(email, phone);
        var bound = store(laptopSession.accessToken(), sdJwt(true), "hk-" + UUID.randomUUID());
        var unbound = store(laptopSession.accessToken(), sdJwt(false), null);

        PasskeyRegistrationIT.withPasskeyCustody(() -> {
            // AC-04: the same (synced) passkey sees it again in a new session
            assertThat(listIds(auth.signIn(laptop).accessToken())).contains(bound, unbound);
            // AC-05 / AC-10: another passkey sees only the unbound one
            assertThat(listIds(phoneSession.accessToken())).contains(unbound).doesNotContain(bound);
            webClient.get().uri("/api/v1/credentials/" + bound)
                    .headers(h -> h.setBearerAuth(phoneSession.accessToken()))
                    .exchange().expectStatus().isNotFound();
            webClient.patch().uri("/api/v1/credentials/" + bound + "/status")
                    .headers(h -> h.setBearerAuth(phoneSession.accessToken()))
                    .bodyValue(Map.of("status", "SUSPENDED"))
                    .exchange().expectStatus().isNotFound();
            webClient.delete().uri("/api/v1/credentials/" + bound)
                    .headers(h -> h.setBearerAuth(phoneSession.accessToken()))
                    .exchange().expectStatus().isNotFound();
        });
        // Other tenants are unchanged: without passkey custody every attestation is listed.
        assertThat(listIds(phoneSession.accessToken())).contains(bound, unbound);
    }

    @Test
    void deletedPasskey_itsAttestationsStayStoredButAreNoLongerListed() {
        // AC-11
        var email = "custody-deleted-" + System.nanoTime() + "@example.com";
        var lost = new SoftwareAuthenticator(TEST_ORIGIN);
        var current = new SoftwareAuthenticator(TEST_ORIGIN);
        var lostSession = auth.signUp(email, lost);
        var currentSession = auth.signUp(email, current);
        var bound = store(lostSession.accessToken(), sdJwt(true), "hk-" + UUID.randomUUID());

        webClient.delete().uri("/api/v1/auth/passkeys/" + lostSession.passkeyId())
                .headers(h -> h.setBearerAuth(currentSession.accessToken()))
                .exchange().expectStatus().isNoContent();

        PasskeyRegistrationIT.withPasskeyCustody(() ->
                assertThat(listIds(auth.signIn(current).accessToken())).doesNotContain(bound));
        assertThat(query("SELECT passkey_id, bound FROM wallet_credential WHERE id = '" + bound + "'"))
                .singleElement().satisfies(row -> {
                    assertThat(row.get("passkey_id")).isNull();
                    assertThat(row).containsEntry("bound", true);
                });
    }

    @Test
    void prfSaltLookup_onlyForAttestationsOfTheSessionPasskey() {
        var email = "custody-salt-" + System.nanoTime() + "@example.com";
        var first = auth.signUp(email, new SoftwareAuthenticator(TEST_ORIGIN));
        var second = auth.signUp(email, new SoftwareAuthenticator(TEST_ORIGIN));
        var holderKey = "holder-" + UUID.randomUUID();
        store(first.accessToken(), sdJwt(true), holderKey);
        var userId = query("SELECT id FROM wallet_user WHERE email = '" + email + "'").get(0).get("id").toString();

        assertThat(obtained(userId, holderKey, first.passkeyId())).isTrue();
        assertThat(obtained(userId, holderKey, second.passkeyId())).isFalse();
        assertThat(obtained(UUID.randomUUID().toString(), holderKey, first.passkeyId())).isFalse();
    }

    private Boolean obtained(String userId, String holderKey, String passkeyId) {
        return sessionPasskeyCredentialPort.isObtainedWithPasskey(userId, holderKey, passkeyId)
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TEST_TENANT))
                .block();
    }

    @SuppressWarnings("unchecked")
    private String store(String accessToken, String credential, String holderKeyId) {
        var body = new java.util.HashMap<String, Object>();
        body.put("credentialResponseWithStatus",
                Map.of("credentialResponse", Map.of("credentials", List.of(Map.of("credential", credential)))));
        body.put("format", "dc+sd-jwt");
        body.put("credentialConfigurationId", "cfg-custody");
        if (holderKeyId != null) {
            body.put("holderKeyId", holderKeyId);
        }
        var stored = webClient.post().uri("/api/v1/openid-credential-offer/credential-response")
                .headers(h -> h.setBearerAuth(accessToken))
                .bodyValue(body)
                .exchange().expectStatus().isOk()
                .expectBody(Map.class).returnResult().getResponseBody();
        return (String) stored.get("id");
    }

    @SuppressWarnings("unchecked")
    private List<String> listIds(String accessToken) {
        List<Map<String, Object>> list = webClient.get().uri("/api/v1/credentials")
                .headers(h -> h.setBearerAuth(accessToken))
                .exchange().expectStatus().isOk()
                .expectBody(List.class).returnResult().getResponseBody();
        return list.stream().map(c -> (String) c.get("id")).toList();
    }

    private static String sdJwt(boolean withCnf) {
        try {
            var key = new ECKeyGenerator(Curve.P_256).generate();
            var claims = new JWTClaimsSet.Builder().issuer("https://issuer.example").subject("did:sub")
                    .claim("vct", "urn:vct:custody");
            if (withCnf) {
                claims.claim("cnf", Map.of("jwk", key.toPublicJWK().toJSONObject()));
            }
            var jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claims.build());
            jwt.sign(new ECDSASigner(key));
            return jwt.serialize() + "~";
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
