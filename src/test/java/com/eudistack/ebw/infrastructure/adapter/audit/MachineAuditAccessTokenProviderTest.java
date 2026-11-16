package com.eudistack.ebw.infrastructure.adapter.audit;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MachineAuditAccessTokenProviderTest {

    private static final String TOKEN_URL = "http://verifier.internal/verifier/oidc/token";
    private static final String CLIENT_ID = "did:key:zMachine";

    private final List<ClientRequest> requests = new ArrayList<>();
    private final AtomicReference<ClientResponse> nextResponse = new AtomicReference<>();
    private MutableClock clock;
    private MachineClientAssertionFactory factory;
    private MachineAuditAccessTokenProvider provider;

    @BeforeEach
    void setUp() throws Exception {
        clock = new MutableClock(Instant.parse("2026-11-06T10:00:00Z"));
        factory = new MachineClientAssertionFactory(CLIENT_ID, "a.b.c",
                new ECKeyGenerator(Curve.P_256).generate().toJSONString(),
                "https://dome.dev.eudistack.net/verifier", clock);
        WebClient webClient = WebClient.builder().exchangeFunction(request -> {
            requests.add(request);
            return Mono.just(nextResponse.get());
        }).build();
        provider = new MachineAuditAccessTokenProvider(webClient, clock, TOKEN_URL, "dome", CLIENT_ID, factory, true);
    }

    private void respondWith(HttpStatus status, String body) {
        nextResponse.set(ClientResponse.create(status)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .body(body)
                .build());
    }

    private void respondWithToken(String token, long expiresIn) {
        respondWith(HttpStatus.OK, "{\"access_token\":\"" + token + "\",\"token_type\":\"Bearer\",\"expires_in\":"
                + expiresIn + "}");
    }

    @Test
    void accessToken_asksTheVerifierAsAMachineForTheTenantAndReturnsTheToken() {
        // Arrange
        respondWithToken("token-1", 899);

        // Act & Assert
        StepVerifier.create(provider.accessToken(null)).expectNext("token-1").verifyComplete();
        assertEquals(1, requests.size());
        assertEquals(HttpMethod.POST, requests.getFirst().method());
        assertEquals(TOKEN_URL, requests.getFirst().url().toString());
        assertEquals("dome", requests.getFirst().headers().getFirst("X-Tenant"));
    }

    @Test
    void accessToken_stillValid_reusesItWithoutAskingAgain() {
        // Arrange
        respondWithToken("token-1", 899);
        provider.accessToken(null).block();
        clock.advance(Duration.ofMinutes(10));

        // Act & Assert
        StepVerifier.create(provider.accessToken(null)).expectNext("token-1").verifyComplete();
        assertEquals(1, requests.size());
    }

    @Test
    void accessToken_aboutToExpire_asksForANewOne() {
        // Arrange
        respondWithToken("token-1", 899);
        provider.accessToken(null).block();
        respondWithToken("token-2", 899);
        clock.advance(Duration.ofSeconds(899 - 59));

        // Act & Assert
        StepVerifier.create(provider.accessToken(null)).expectNext("token-2").verifyComplete();
        assertEquals(2, requests.size());
    }

    @Test
    void refreshAccessToken_alwaysAsksAgainEvenIfTheCachedOneHasNotExpired() {
        // Arrange
        respondWithToken("token-1", 899);
        provider.accessToken(null).block();
        respondWithToken("token-2", 899);

        // Act & Assert
        StepVerifier.create(provider.refreshAccessToken(null)).expectNext("token-2").verifyComplete();
        StepVerifier.create(provider.accessToken(null)).expectNext("token-2").verifyComplete();
        assertEquals(2, requests.size());
    }

    @Test
    void accessToken_responseWithoutAccessToken_fails() {
        respondWith(HttpStatus.OK, "{\"token_type\":\"Bearer\"}");

        StepVerifier.create(provider.accessToken(null)).expectError(IllegalStateException.class).verify();
    }

    @Test
    void accessToken_verifierRejectsTheMachine_failsWithoutEchoingTheResponse() {
        // Arrange
        respondWith(HttpStatus.UNAUTHORIZED, "{\"detail\":\"secret-detail\"}");

        // Act & Assert
        StepVerifier.create(provider.accessToken(null))
                .expectErrorSatisfies(error -> {
                    assertTrue(error instanceof IllegalStateException);
                    assertTrue(error.getMessage().contains("did not issue an access token"));
                    assertTrue(!error.getMessage().contains("secret-detail"));
                })
                .verify();
    }

    @Test
    void constructor_withoutATokenUrl_failsNamingTheVariable() {
        WebClient webClient = WebClient.create();
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> new MachineAuditAccessTokenProvider(webClient, clock, "", "dome", CLIENT_ID, factory, true));

        assertEquals("AUDIT_M2M_TOKEN_URL is not set", error.getMessage());
    }

    @Test
    void constructor_withoutATenant_failsBecauseTheVerifierResolvesTheMachineByIt() {
        WebClient webClient = WebClient.create();
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> new MachineAuditAccessTokenProvider(webClient, clock, TOKEN_URL, " ", CLIENT_ID,
                        factory, true));

        assertEquals("AUDIT_M2M_TENANT is not set", error.getMessage());
    }

    @Test
    void accessToken_lifetimeShorterThanTheMargin_isRenewedAtHalfItsLifeNotOnEveryBatch() {
        // Arrange
        respondWithToken("token-1", 40);
        provider.accessToken(null).block();
        clock.advance(Duration.ofSeconds(10));

        // Act & Assert
        StepVerifier.create(provider.accessToken(null)).expectNext("token-1").verifyComplete();
        assertEquals(1, requests.size());
        clock.advance(Duration.ofSeconds(11));
        respondWithToken("token-2", 40);
        StepVerifier.create(provider.accessToken(null)).expectNext("token-2").verifyComplete();
        assertEquals(2, requests.size());
    }

    @Test
    void accessToken_manyCallsWhileRenewing_shareOneRequest() {
        // Arrange
        respondWithToken("token-1", 899);
        ClientResponse response = nextResponse.get();
        List<ClientRequest> seen = new ArrayList<>();
        WebClient slowWebClient = WebClient.builder().exchangeFunction(request -> {
            seen.add(request);
            return Mono.just(response).delayElement(Duration.ofMillis(50));
        }).build();
        MachineAuditAccessTokenProvider slow = new MachineAuditAccessTokenProvider(
                slowWebClient, clock, TOKEN_URL, "dome", CLIENT_ID, factory, true);

        // Act
        Mono<String> both = Mono.zip(slow.accessToken(null), slow.accessToken(null), (first, second) -> first + second);

        // Assert
        StepVerifier.create(both).expectNext("token-1token-1").verifyComplete();
        assertEquals(1, seen.size());
    }

    @Test
    void constructor_tokenUrlOverPlainHttp_isRefusedUnlessTheLocalSwitchIsOn() {
        WebClient webClient = WebClient.create();
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> new MachineAuditAccessTokenProvider(webClient, clock, TOKEN_URL, "dome", CLIENT_ID, factory, false));

        assertTrue(error.getMessage().startsWith("AUDIT_M2M_TOKEN_URL must be https"));
    }

    @Test
    void constructor_httpsOrLoopbackTokenUrl_isAcceptedWithoutTheSwitch() {
        WebClient webClient = WebClient.create();

        new MachineAuditAccessTokenProvider(webClient, clock, "https://dome.dev.eudistack.net/verifier/oidc/token",
                "dome", CLIENT_ID, factory, false);
        new MachineAuditAccessTokenProvider(webClient, clock, "http://localhost:8082/verifier/oidc/token",
                "dome", CLIENT_ID, factory, false);
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant start) {
            this.now = start;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
