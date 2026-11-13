package com.eudistack.ebw.infrastructure.adapter.verifier;

import com.eudistack.ebw.infrastructure.adapter.properties.VerifierProperties;
import com.eudistack.ebw.support.FakeVerifierServer;
import com.eudistack.ebw.support.TestSystemTokens;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/** Unit tests for {@link VerifierJwksClient} against a local HTTP Verifier (ES-03, ES-04). */
class VerifierJwksClientTest {

    private final TestSystemTokens keys = new TestSystemTokens();
    private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-10-27T10:00:00Z"));
    private FakeVerifierServer verifier;
    private VerifierJwksClient client;

    @BeforeEach
    void setUp() {
        verifier = new FakeVerifierServer(keys.publicJwks());
        client = client(verifier.internalUrl());
    }

    @AfterEach
    void tearDown() {
        verifier.close();
    }

    private VerifierJwksClient client(String internalUrl) {
        Clock clock = new Clock() {
            @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(java.time.ZoneId zone) { return this; }
            @Override public Instant instant() { return now.get(); }
        };
        return new VerifierJwksClient(WebClient.create(), new VerifierProperties(internalUrl, "/verifier"), clock);
    }

    @Test
    void keys_readsThroughDiscoveryOnTheInternalOrigin_andCachesTenMinutes() {
        // Act + Assert
        StepVerifier.create(client.keys())
                .assertNext(set -> assertThat(set.getKeyByKeyId(keys.kid())).isNotNull())
                .verifyComplete();
        StepVerifier.create(client.keys()).expectNextCount(1).verifyComplete();
        assertThat(verifier.jwksReads()).isEqualTo(1);

        now.set(now.get().plus(VerifierJwksClient.CACHE_TTL).plusSeconds(1));
        StepVerifier.create(client.keys()).expectNextCount(1).verifyComplete();
        assertThat(verifier.jwksReads()).isEqualTo(2);
    }

    @Test
    void reload_readsAgainOnlyAfterTheMinimumInterval() {
        // Arrange
        StepVerifier.create(client.keys()).expectNextCount(1).verifyComplete();
        var rotated = new TestSystemTokens();
        verifier.setJwks(rotated.publicJwks());

        // Act + Assert
        StepVerifier.create(client.reload()).expectNextCount(1).verifyComplete();
        assertThat(verifier.jwksReads()).isEqualTo(1);

        now.set(now.get().plus(VerifierJwksClient.MIN_RELOAD_INTERVAL).plusSeconds(1));
        StepVerifier.create(client.reload())
                .assertNext(set -> assertThat(set.getKeyByKeyId(rotated.kid())).isNotNull())
                .verifyComplete();
        assertThat(verifier.jwksReads()).isEqualTo(2);
    }

    @Test
    void keys_verifierDownWithoutCopy_failsUnavailable() {
        // Arrange
        verifier.setAvailable(false);

        // Act + Assert
        StepVerifier.create(client.keys()).expectError(VerifierUnavailableException.class).verify();
    }

    @Test
    void keys_verifierDownWithStaleCopy_usesTheLastOneRead() {
        // Arrange
        StepVerifier.create(client.keys()).expectNextCount(1).verifyComplete();
        verifier.setAvailable(false);
        now.set(now.get().plus(VerifierJwksClient.CACHE_TTL).plusSeconds(1));

        // Act + Assert
        StepVerifier.create(client.keys())
                .assertNext(set -> assertThat(set.getKeyByKeyId(keys.kid())).isNotNull())
                .verifyComplete();
    }

    @Test
    void keys_verifierDownWithStaleCopy_triesTheVerifierAtMostOncePerInterval() {
        // Arrange: unauthenticated requests must not multiply the reads of a Verifier that is down
        StepVerifier.create(client.keys()).expectNextCount(1).verifyComplete();
        verifier.setAvailable(false);
        now.set(now.get().plus(VerifierJwksClient.CACHE_TTL).plusSeconds(1));

        // Act
        for (int i = 0; i < 3; i++) {
            StepVerifier.create(client.keys()).expectNextCount(1).verifyComplete();
            StepVerifier.create(client.reload()).expectNextCount(1).verifyComplete();
        }

        // Assert: one read at start, one failed attempt for the six calls
        assertThat(verifier.discoveryReads()).isEqualTo(2);
        now.set(now.get().plus(VerifierJwksClient.MIN_RELOAD_INTERVAL).plusSeconds(1));
        StepVerifier.create(client.keys()).expectNextCount(1).verifyComplete();
        assertThat(verifier.discoveryReads()).isEqualTo(3);
    }

    @Test
    void keys_verifierDownWithoutCopy_failsWithoutTryingAgainWithinTheInterval() {
        // Arrange
        verifier.setAvailable(false);

        // Act + Assert
        StepVerifier.create(client.keys()).expectError(VerifierUnavailableException.class).verify();
        StepVerifier.create(client.keys()).expectError(VerifierUnavailableException.class).verify();
        StepVerifier.create(client.reload()).expectError(VerifierUnavailableException.class).verify();
        assertThat(verifier.discoveryReads()).isEqualTo(1);
    }

    @Test
    void keys_concurrentReads_shareOneRequest() {
        // Act
        StepVerifier.create(Mono.zip(client.keys(), client.keys(), client.reload()))
                .expectNextCount(1)
                .verifyComplete();

        // Assert
        assertThat(verifier.discoveryReads()).isEqualTo(1);
        assertThat(verifier.jwksReads()).isEqualTo(1);
    }

    @Test
    void keys_notConfigured_failsUnavailable() {
        // Act + Assert
        StepVerifier.create(client("").keys()).expectError(VerifierUnavailableException.class).verify();
    }

    @Test
    void toInternal_keepsThePublicPathAndSwapsTheOrigin() {
        // Act + Assert
        assertThat(client("http://verifier-service:8080/verifier")
                .toInternal("https://sandbox.stg.eudistack.net/verifier/oidc/jwks"))
                .isEqualTo("http://verifier-service:8080/verifier/oidc/jwks");
    }
}
