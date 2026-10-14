package com.eudistack.ebw.support;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Map;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Drives the registration and access API like the Wallet App does, against a running
 * application: email code, registration ticket, WebAuthn ceremonies with a
 * {@link SoftwareAuthenticator}, refresh cookie. {@code otps} is the map where the test's
 * mocked {@code EmailSender} captures the codes sent.
 */
public class WalletAuthClient {

    public static final String WALLET_REQUEST = "X-Wallet-Request";
    public static final String COOKIE = "__Host-wallet_refresh";

    private final WebTestClient client;
    private final Map<String, String> otps;
    private final Consumer<HttpHeaders> tenantHeaders;
    private final String origin;

    /** Session opened by the service: access token, passkey and the raw refresh cookie value. */
    public record Session(String accessToken, String passkeyId, String refreshToken, String setCookie) {}

    public WalletAuthClient(WebTestClient client, Map<String, String> otps, Consumer<HttpHeaders> tenantHeaders,
                            String origin) {
        this.client = client;
        this.otps = otps;
        this.tenantHeaders = tenantHeaders;
        this.origin = origin;
    }

    public String origin() {
        return origin;
    }

    /** {@code tenant_config} of a tenant schema: Relying Party on {@code rpId}, Wallet App on {@code origin}. */
    public static void configureRelyingParty(Connection conn, String schema, String rpId, String origin)
            throws SQLException {
        conn.createStatement().execute("INSERT INTO " + schema + ".tenant_config (config_key, config_value) VALUES "
                + "('ebw.webauthn.rp_id', '" + rpId + "'), ('ebw.webauthn.origins', '" + origin + "') "
                + "ON CONFLICT (config_key) DO UPDATE SET config_value = EXCLUDED.config_value");
    }

    // ------------------------------------------------------------------ email verification

    public WebTestClient.ResponseSpec requestCode(String email) {
        return client.post().uri("/api/v1/auth/register").headers(tenantHeaders)
                .bodyValue(Map.of("email", email)).exchange();
    }

    public WebTestClient.ResponseSpec verifyCode(String email, String code) {
        return client.post().uri("/api/v1/auth/verify-email").headers(tenantHeaders)
                .bodyValue(Map.of("email", email, "code", code)).exchange();
    }

    /** Email code and its verification: the registration ticket body. */
    @SuppressWarnings("unchecked")
    public Map<String, Object> verifyEmail(String email) {
        requestCode(email).expectStatus().isAccepted();
        var code = otps.get(email);
        assertThat(code).as("code sent to " + email).isNotNull();
        return verifyCode(email, code).expectStatus().isOk().expectBody(Map.class).returnResult().getResponseBody();
    }

    public String ticket(String email) {
        return (String) verifyEmail(email).get("registrationTicket");
    }

    // ------------------------------------------------------------------ passkey registration

    public WebTestClient.ResponseSpec registrationOptionsSpec(String ticket) {
        return client.post().uri("/api/v1/auth/passkeys/registration/options").headers(tenantHeaders)
                .headers(h -> bearer(h, ticket)).exchange();
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> registrationOptions(String ticket) {
        return registrationOptionsSpec(ticket).expectStatus().isOk().expectBody(Map.class).returnResult()
                .getResponseBody();
    }

    public WebTestClient.ResponseSpec registerSpec(String ticket, Object ceremonyId, Map<String, Object> credential,
                                                   Boolean prfSupported, String cookie) {
        var body = new java.util.HashMap<String, Object>();
        body.put("ceremonyId", ceremonyId);
        body.put("credential", credential);
        if (prfSupported != null) {
            body.put("prfSupported", prfSupported);
        }
        body.put("displayName", "Test device");
        return client.post().uri("/api/v1/auth/passkeys/registration").headers(tenantHeaders)
                .headers(h -> {
                    bearer(h, ticket);
                    h.add(WALLET_REQUEST, "1");
                })
                .cookies(c -> cookie(c, cookie))
                .bodyValue(body).exchange();
    }

    /** Options + {@code navigator.credentials.create} + registration, with PRF support. */
    @SuppressWarnings("unchecked")
    public WebTestClient.ResponseSpec registerPasskeySpec(String ticket, SoftwareAuthenticator authenticator,
                                                          String cookie) {
        var options = registrationOptions(ticket);
        var credential = authenticator.register((Map<String, Object>) options.get("publicKey"));
        return registerSpec(ticket, options.get("ceremonyId"), credential, true, cookie);
    }

    public Session registerPasskey(String ticket, SoftwareAuthenticator authenticator) {
        return session(registerPasskeySpec(ticket, authenticator, null).expectStatus().isCreated());
    }

    /** New account (or existing one) with a new passkey: the session it opens. */
    public Session signUp(String email, SoftwareAuthenticator authenticator) {
        return registerPasskey(ticket(email), authenticator);
    }

    // ------------------------------------------------------------------ sign-in

    public WebTestClient.ResponseSpec authenticationOptionsSpec(String ticket) {
        return client.post().uri("/api/v1/auth/sessions/options").headers(tenantHeaders)
                .headers(h -> bearer(h, ticket)).exchange();
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> authenticationOptions(String ticket) {
        return authenticationOptionsSpec(ticket).expectStatus().isOk().expectBody(Map.class).returnResult()
                .getResponseBody();
    }

    public WebTestClient.ResponseSpec openSessionSpec(String ticket, Object ceremonyId, Map<String, Object> credential,
                                                      String cookie) {
        return client.post().uri("/api/v1/auth/sessions").headers(tenantHeaders)
                .headers(h -> {
                    bearer(h, ticket);
                    h.add(WALLET_REQUEST, "1");
                })
                .cookies(c -> cookie(c, cookie))
                .bodyValue(Map.of("ceremonyId", ceremonyId, "credential", credential)).exchange();
    }

    /** Options + {@code navigator.credentials.get} + session. */
    @SuppressWarnings("unchecked")
    public WebTestClient.ResponseSpec signInSpec(SoftwareAuthenticator authenticator, String ticket, String cookie) {
        var options = authenticationOptions(ticket);
        var credential = authenticator.authenticate((Map<String, Object>) options.get("publicKey"));
        return openSessionSpec(ticket, options.get("ceremonyId"), credential, cookie);
    }

    public Session signIn(SoftwareAuthenticator authenticator) {
        return session(signInSpec(authenticator, null, null).expectStatus().isCreated());
    }

    // ------------------------------------------------------------------ session

    public WebTestClient.ResponseSpec refreshSpec(String refreshToken, boolean walletRequestHeader) {
        return client.post().uri("/api/v1/auth/refresh").headers(tenantHeaders)
                .cookies(c -> cookie(c, refreshToken))
                .headers(h -> {
                    if (walletRequestHeader) {
                        h.add(WALLET_REQUEST, "1");
                    }
                })
                .exchange();
    }

    public Session refresh(String refreshToken) {
        return session(refreshSpec(refreshToken, true).expectStatus().isOk());
    }

    public WebTestClient.ResponseSpec endSessionSpec(String path, String accessToken, boolean walletRequestHeader) {
        return client.delete().uri("/api/v1/auth/sessions/" + path).headers(tenantHeaders)
                .headers(h -> {
                    if (accessToken != null) {
                        h.setBearerAuth(accessToken);
                    }
                    if (walletRequestHeader) {
                        h.add(WALLET_REQUEST, "1");
                    }
                })
                .exchange();
    }

    @SuppressWarnings("unchecked")
    public static Session session(WebTestClient.ResponseSpec spec) {
        var result = spec.expectBody(Map.class).returnResult();
        var setCookie = result.getResponseHeaders().getFirst(HttpHeaders.SET_COOKIE);
        assertThat(setCookie).as("refresh cookie").isNotNull();
        var cookie = ResponseCookie.from(COOKIE, setCookie.substring(setCookie.indexOf('=') + 1,
                setCookie.indexOf(';'))).build();
        Map<String, Object> body = result.getResponseBody();
        assertThat(body).doesNotContainKey("refreshToken");
        return new Session((String) body.get("accessToken"), (String) body.get("passkeyId"), cookie.getValue(),
                setCookie);
    }

    private static void bearer(HttpHeaders headers, String token) {
        if (token != null) {
            headers.setBearerAuth(token);
        }
    }

    private static void cookie(org.springframework.util.MultiValueMap<String, String> cookies, String refreshToken) {
        if (refreshToken != null) {
            cookies.add(COOKIE, refreshToken);
        }
    }
}
