package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.infrastructure.adapter.properties.RateLimitProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;

import java.net.InetSocketAddress;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ClientIpResolver} — the client address is counted from the end of
 * {@code X-Forwarded-For} by the number of trusted proxies, so the first (client-controlled) value never decides it.
 */
class ClientIpResolverTest {

    private static final String PEER = "10.0.0.1";

    private static ClientIpResolver resolverWithProxies(int proxies) {
        return new ClientIpResolver(
                new RateLimitProperties(10, 10, 10, 10, 10, 10, 10, 10, proxies, Duration.ofHours(1)));
    }

    private static MockServerHttpRequest.BaseBuilder<?> request() {
        return MockServerHttpRequest.post("/api/v1/auth/register")
                .remoteAddress(new InetSocketAddress(PEER, 443));
    }

    @Nested
    @DisplayName("With CloudFront and the ALB in front (2 proxies)")
    class TwoProxies {

        private final ClientIpResolver resolver = resolverWithProxies(2);

        @Test
        void resolve_threeEntries_returnsTheSecondFromTheEnd() {
            // Arrange
            ServerHttpRequest request = request()
                    .header("X-Forwarded-For", "198.51.100.1, 203.0.113.7, 10.0.0.9").build();

            // Act
            var ip = resolver.resolve(request);

            // Assert
            assertThat(ip).isEqualTo("203.0.113.7");
        }

        @Test
        void resolve_clientChangesTheFirstValue_returnsTheSameAddress() {
            // Arrange
            ServerHttpRequest first = request()
                    .header("X-Forwarded-For", "198.51.100.1, 203.0.113.7, 10.0.0.9").build();
            ServerHttpRequest second = request()
                    .header("X-Forwarded-For", "192.0.2.55, 203.0.113.7, 10.0.0.9").build();

            // Act
            var firstIp = resolver.resolve(first);
            var secondIp = resolver.resolve(second);

            // Assert
            assertThat(firstIp).isEqualTo(secondIp).isEqualTo("203.0.113.7");
        }

        @Test
        void resolve_clientSendsMoreEntries_stillReturnsTheSecondFromTheEnd() {
            // Arrange
            ServerHttpRequest request = request()
                    .header("X-Forwarded-For", "1.1.1.1, 2.2.2.2, 3.3.3.3, 203.0.113.7, 10.0.0.9").build();

            // Act
            var ip = resolver.resolve(request);

            // Assert
            assertThat(ip).isEqualTo("203.0.113.7");
        }

        @Test
        void resolve_fewerEntriesThanProxies_returnsThePeerAddress() {
            // Arrange
            ServerHttpRequest request = request().header("X-Forwarded-For", "203.0.113.7").build();

            // Act
            var ip = resolver.resolve(request);

            // Assert
            assertThat(ip).isEqualTo(PEER);
        }

        @Test
        void resolve_headerSplitInSeveralLines_joinsThemInOrder() {
            // Arrange
            ServerHttpRequest request = request()
                    .header("X-Forwarded-For", "198.51.100.1")
                    .header("X-Forwarded-For", "203.0.113.7, 10.0.0.9").build();

            // Act
            var ip = resolver.resolve(request);

            // Assert
            assertThat(ip).isEqualTo("203.0.113.7");
        }

        @Test
        void resolve_emptyEntries_areIgnored() {
            // Arrange
            ServerHttpRequest request = request()
                    .header("X-Forwarded-For", " , 203.0.113.7 ,, 10.0.0.9 , ").build();

            // Act
            var ip = resolver.resolve(request);

            // Assert
            assertThat(ip).isEqualTo("203.0.113.7");
        }

        @Test
        void resolve_ipv6Entry_isKeyedByItsSixtyFourBitPrefix() {
            // Arrange
            ServerHttpRequest request = request()
                    .header("X-Forwarded-For", "198.51.100.1, 2001:db8:1:2:aaaa:bbbb:cccc:dddd, 10.0.0.9").build();

            // Act
            var ip = resolver.resolve(request);

            // Assert
            assertThat(ip).isEqualTo("2001:0db8:0001:0002::/64");
        }

        @Test
        void resolve_ipv6AddressesOfTheSamePrefix_returnTheSameKey() {
            // Arrange
            ServerHttpRequest first = request()
                    .header("X-Forwarded-For", "198.51.100.1, 2001:db8:1:2::1, 10.0.0.9").build();
            ServerHttpRequest second = request()
                    .header("X-Forwarded-For", "198.51.100.1, 2001:db8:1:2:ffff:ffff:ffff:ffff, 10.0.0.9").build();

            // Act
            var firstIp = resolver.resolve(first);
            var secondIp = resolver.resolve(second);

            // Assert
            assertThat(firstIp).isEqualTo(secondIp);
        }

        @Test
        void resolve_ipv6AddressesOfDifferentPrefixes_returnDifferentKeys() {
            // Arrange
            ServerHttpRequest first = request()
                    .header("X-Forwarded-For", "198.51.100.1, 2001:db8:1:2::1, 10.0.0.9").build();
            ServerHttpRequest second = request()
                    .header("X-Forwarded-For", "198.51.100.1, 2001:db8:1:3::1, 10.0.0.9").build();

            // Act
            var firstIp = resolver.resolve(first);
            var secondIp = resolver.resolve(second);

            // Assert
            assertThat(firstIp).isNotEqualTo(secondIp);
        }

        @Test
        void resolve_ipv4MappedIpv6Entry_returnsTheIpv4Address() {
            // Arrange
            ServerHttpRequest request = request()
                    .header("X-Forwarded-For", "198.51.100.1, ::ffff:203.0.113.7, 10.0.0.9").build();

            // Act
            var ip = resolver.resolve(request);

            // Assert
            assertThat(ip).isEqualTo("203.0.113.7");
        }

        @Test
        void resolve_ipv4WithLeadingZeros_returnsTheCanonicalAddress() {
            // Arrange
            ServerHttpRequest request = request()
                    .header("X-Forwarded-For", "198.51.100.1, 203.000.113.007, 10.0.0.9").build();

            // Act
            var ip = resolver.resolve(request);

            // Assert
            assertThat(ip).isEqualTo("203.0.113.7");
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "198.51.100.1, not-an-ip, 10.0.0.9",
                "198.51.100.1, 203.0.113.7:8080:extra:more:more:more:more:more:more, 10.0.0.9",
                "198.51.100.1, 12345, 10.0.0.9",
                "198.51.100.1, 999.1.1.1, 10.0.0.9",
                "198.51.100.1, dead.beef, 10.0.0.9",
                "198.51.100.1, :::, 10.0.0.9",
                "198.51.100.1, <script>, 10.0.0.9"})
        void resolve_selectedEntryIsNotAnIpAddress_fallsBackToThePeerAddress(String forwardedFor) {
            // Arrange
            ServerHttpRequest request = request().header("X-Forwarded-For", forwardedFor).build();

            // Act
            var ip = resolver.resolve(request);

            // Assert
            assertThat(ip).isEqualTo(PEER);
        }
    }

    @Nested
    @DisplayName("Without any proxy in front")
    class NoHeader {

        @Test
        void resolve_noForwardedHeader_returnsThePeerAddress() {
            // Arrange
            ServerHttpRequest request = request().build();

            // Act
            var ip = resolverWithProxies(2).resolve(request);

            // Assert
            assertThat(ip).isEqualTo(PEER);
        }

        @Test
        void resolve_noHeaderAndAnIpv6Peer_returnsThePeerSixtyFourBitPrefix() {
            // Arrange
            ServerHttpRequest request = MockServerHttpRequest.post("/api/v1/auth/register")
                    .remoteAddress(new InetSocketAddress("2001:db8:1:2::5", 443)).build();

            // Act
            var ip = resolverWithProxies(2).resolve(request);

            // Assert
            assertThat(ip).isEqualTo("2001:0db8:0001:0002::/64");
        }

        @Test
        void resolve_noHeaderAndNoPeerAddress_returnsUnknown() {
            // Arrange
            ServerHttpRequest request = MockServerHttpRequest.post("/api/v1/auth/register").build();

            // Act
            var ip = resolverWithProxies(2).resolve(request);

            // Assert
            assertThat(ip).isEqualTo("unknown");
        }
    }

    @Test
    void resolve_oneProxy_returnsTheLastEntry() {
        // Arrange
        ServerHttpRequest request = request().header("X-Forwarded-For", "198.51.100.1, 203.0.113.7").build();

        // Act
        var ip = resolverWithProxies(1).resolve(request);

        // Assert
        assertThat(ip).isEqualTo("203.0.113.7");
    }

    @Test
    void resolve_oneProxyAndOneEntry_returnsThatEntry() {
        // Arrange
        ServerHttpRequest request = request().header("X-Forwarded-For", "203.0.113.7").build();

        // Act
        var ip = resolverWithProxies(1).resolve(request);

        // Assert
        assertThat(ip).isEqualTo("203.0.113.7");
    }
}
