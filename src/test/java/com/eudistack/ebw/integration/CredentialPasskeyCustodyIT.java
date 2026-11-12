package com.eudistack.ebw.integration;

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
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * EUD-11 FR-13/FR-14 with passkey custody: a bound attestation is stored with the session's
 * passkey and only listed to sessions of that passkey; unbound ones are listed to every session
 * (AC-04, AC-05, AC-10, AC-11). The salt and public key of an attestation are only given to the same passkey
 * (FR-14, AC-08), the key of a stored attestation must be the key of its holder (FR-05, AC-05) and deleting an
 * attestation deletes its salt (FR-16, AC-06).
 */
class CredentialPasskeyCustodyIT extends IntegrationTestBase {

    private static final String SALTS = "/api/v1/keys/passkey-prf/salts";

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
    void passkeySalts_onlyThePasskeyOfTheAttestationGetsItsSaltAndPublicKey() {
        // AC-08
        var email = "custody-salt-" + System.nanoTime() + "@example.com";
        var first = auth.signUp(email, new SoftwareAuthenticator(TEST_ORIGIN));
        var second = auth.signUp(email, new SoftwareAuthenticator(TEST_ORIGIN));
        var credentialId = "holder-" + UUID.randomUUID();
        var attestation = boundSdJwt();

        PasskeyRegistrationIT.withPasskeyCustody(() -> {
            createSalt(first.accessToken(), credentialId).expectStatus().isCreated()
                    .expectBody()
                    .jsonPath("$.prf_salt").isNotEmpty()
                    .jsonPath("$.kdf.algorithm").isEqualTo("HKDF-SHA-256")
                    .jsonPath("$.kdf.info").isEqualTo("eudistack:passkey-prf:p256:v1");
            createSalt(second.accessToken(), credentialId).expectStatus().isNotFound();
            getSalt(first.accessToken(), credentialId).expectStatus().isNotFound();

            storeRequest(first.accessToken(), attestation.compact(), credentialId, attestation.publicJwk())
                    .expectStatus().isOk();

            getSalt(first.accessToken(), credentialId).expectStatus().isOk()
                    .expectBody().jsonPath("$.public_jwk.x").isEqualTo(attestation.publicJwk().get("x"));
            getSalt(second.accessToken(), credentialId).expectStatus().isNotFound();
        });
    }

    @Test
    void passkeyCustodyStore_cnfIsNotTheHolderKey_returns422AndStoresNothing() {
        // AC-05
        var email = "custody-mismatch-" + System.nanoTime() + "@example.com";
        var session = auth.signUp(email, new SoftwareAuthenticator(TEST_ORIGIN));
        var credentialId = "holder-" + UUID.randomUUID();
        var attestation = boundSdJwt();
        var otherKey = generateKey().toPublicJWK().toJSONObject();

        PasskeyRegistrationIT.withPasskeyCustody(() -> {
            createSalt(session.accessToken(), credentialId).expectStatus().isCreated();

            storeRequest(session.accessToken(), attestation.compact(), credentialId, otherKey)
                    .expectStatus().isEqualTo(422);
        });

        assertThat(query("SELECT 1 FROM wallet_credential c JOIN wallet_user u ON u.id = c.user_id "
                + "WHERE u.email = '" + email + "'")).isEmpty();
    }

    @Test
    void passkeyCustodyDelete_removesTheSaltOfTheAttestation() {
        // AC-06
        var email = "custody-delete-" + System.nanoTime() + "@example.com";
        var session = auth.signUp(email, new SoftwareAuthenticator(TEST_ORIGIN));
        var credentialId = "holder-" + UUID.randomUUID();
        var attestation = boundSdJwt();

        PasskeyRegistrationIT.withPasskeyCustody(() -> {
            createSalt(session.accessToken(), credentialId).expectStatus().isCreated();
            var id = idOf(storeRequest(session.accessToken(), attestation.compact(), credentialId, attestation.publicJwk()));
            assertThat(query("SELECT 1 FROM passkey_prf_salt WHERE credential_id = '" + credentialId + "'")).hasSize(1);

            webClient.delete().uri("/api/v1/credentials/" + id)
                    .headers(h -> h.setBearerAuth(session.accessToken()))
                    .exchange().expectStatus().isNoContent();
        });

        assertThat(query("SELECT 1 FROM passkey_prf_salt WHERE credential_id = '" + credentialId + "'")).isEmpty();
    }

    private WebTestClient.ResponseSpec createSalt(String accessToken, String credentialId) {
        return webClient.post().uri(SALTS)
                .headers(h -> h.setBearerAuth(accessToken))
                .bodyValue(Map.of("credential_id", credentialId))
                .exchange();
    }

    private WebTestClient.ResponseSpec getSalt(String accessToken, String credentialId) {
        return webClient.get().uri(SALTS + "/" + credentialId)
                .headers(h -> h.setBearerAuth(accessToken))
                .exchange();
    }

    @SuppressWarnings("unchecked")
    private String idOf(WebTestClient.ResponseSpec stored) {
        return (String) stored.expectStatus().isOk()
                .expectBody(Map.class).returnResult().getResponseBody().get("id");
    }

    private String store(String accessToken, String credential, String holderKeyId) {
        return idOf(storeRequest(accessToken, credential, holderKeyId, null));
    }

    private WebTestClient.ResponseSpec storeRequest(String accessToken, String credential, String holderKeyId,
                                                    Map<String, Object> holderPublicJwk) {
        var body = new java.util.HashMap<String, Object>();
        body.put("credentialResponseWithStatus",
                Map.of("credentialResponse", Map.of("credentials", List.of(Map.of("credential", credential)))));
        body.put("format", "dc+sd-jwt");
        body.put("credentialConfigurationId", "cfg-custody");
        if (holderKeyId != null) {
            body.put("holderKeyId", holderKeyId);
        }
        if (holderPublicJwk != null) {
            body.put("holder_public_jwk", holderPublicJwk);
        }
        return webClient.post().uri("/api/v1/openid-credential-offer/credential-response")
                .headers(h -> h.setBearerAuth(accessToken))
                .bodyValue(body)
                .exchange();
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
        return withCnf ? boundSdJwt().compact() : unboundSdJwt();
    }

    private record Attestation(String compact, Map<String, Object> publicJwk) {
    }

    private static Attestation boundSdJwt() {
        var key = generateKey();
        return new Attestation(signedSdJwt(key, true), key.toPublicJWK().toJSONObject());
    }

    private static String unboundSdJwt() {
        return signedSdJwt(generateKey(), false);
    }

    private static com.nimbusds.jose.jwk.ECKey generateKey() {
        try {
            return new ECKeyGenerator(Curve.P_256).generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String signedSdJwt(com.nimbusds.jose.jwk.ECKey key, boolean withCnf) {
        try {
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
