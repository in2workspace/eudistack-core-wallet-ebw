package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link TenantDomainWebFilter} tenant resolution.
 *
 * <p>Covers all branches of both {@code trust-forwarded-host} modes:
 * <ul>
 *   <li>false (default) — subdomain of {@code Host} header only
 *   <li>true — {@code X-Tenant}, then {@code X-Forwarded-Host}, then {@code Host} fallback
 * </ul>
 */
class TenantDomainWebFilterTest {

    // -------------------------------------------------------------------------
    // trust-forwarded-host = false (default)
    // -------------------------------------------------------------------------

    @Nested
    class TrustForwardedHostDisabled {

        private final TenantDomainWebFilter filter = new TenantDomainWebFilter(false);

        @Test
        void hostWithSubdomain_returnsTenant() {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header("Host", "acme.example.com"));

            assertThat(filter.resolveTenant(exchange)).isEqualTo("acme");
        }

        @Test
        void hostWithPort_stripsPortBeforeExtraction() {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header("Host", "acme.example.com:8080"));

            assertThat(filter.resolveTenant(exchange)).isEqualTo("acme");
        }

        @Test
        void uppercaseHost_normalisesToLowercase() {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header("Host", "ACME.example.com"));

            assertThat(filter.resolveTenant(exchange)).isEqualTo("acme");
        }

        @Test
        void hostWithoutDot_returnsNull() {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header("Host", "localhost"));

            assertThat(filter.resolveTenant(exchange)).isNull();
        }

        @Test
        void hostWithLeadingDot_returnsNull() {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header("Host", ".example.com"));

            assertThat(filter.resolveTenant(exchange)).isNull();
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "1tenant.example.com",
                "-tenant.example.com",
                "_tenant.example.com"
        })
        void subdomainStartingWithNonLetter_returnsNull(String host) {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header("Host", host));

            assertThat(filter.resolveTenant(exchange)).isNull();
        }

        @Test
        void noHostHeader_returnsNull() {
            var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());

            assertThat(filter.resolveTenant(exchange)).isNull();
        }

        @Test
        void xForwardedHostPresent_isIgnoredWhenTrustDisabled() {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header("Host", "trustedhost.example.com")
                    .header(TenantDomainWebFilter.HEADER_X_FORWARDED_HOST, "other.example.com"));

            assertThat(filter.resolveTenant(exchange)).isEqualTo("trustedhost");
        }

        @Test
        void xTenantPresent_isIgnoredWhenTrustDisabled() {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header("Host", "fromhost.example.com")
                    .header(TenantDomainWebFilter.HEADER_X_TENANT, "fromheader"));

            assertThat(filter.resolveTenant(exchange)).isEqualTo("fromhost");
        }
    }

    // -------------------------------------------------------------------------
    // trust-forwarded-host = true
    // -------------------------------------------------------------------------

    @Nested
    class TrustForwardedHostEnabled {

        private final TenantDomainWebFilter filter = new TenantDomainWebFilter(true);

        @Test
        void xTenantPresent_returnsTenant() {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header(TenantDomainWebFilter.HEADER_X_TENANT, "acme"));

            assertThat(filter.resolveTenant(exchange)).isEqualTo("acme");
        }

        @Test
        void xTenantHasPriorityOverXForwardedHost() {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header(TenantDomainWebFilter.HEADER_X_TENANT, "fromtenant")
                    .header(TenantDomainWebFilter.HEADER_X_FORWARDED_HOST, "fromforwarded.example.com")
                    .header("Host", "fromhost.example.com"));

            assertThat(filter.resolveTenant(exchange)).isEqualTo("fromtenant");
        }

        @Test
        void xTenantUppercase_normalisesToLowercase() {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header(TenantDomainWebFilter.HEADER_X_TENANT, "ACME"));

            assertThat(filter.resolveTenant(exchange)).isEqualTo("acme");
        }

        @Test
        void xTenantWithLeadingTrailingSpaces_isTrimmedAndAccepted() {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header(TenantDomainWebFilter.HEADER_X_TENANT, "  acme  "));

            assertThat(filter.resolveTenant(exchange)).isEqualTo("acme");
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "1tenant",
                "-tenant",
                "tenant.with.dot",
                "tenant with space"
        })
        void xTenantWithInvalidFormat_fallsBackToHost(String xTenantValue) {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header(TenantDomainWebFilter.HEADER_X_TENANT, xTenantValue)
                    .header("Host", "fromhost.example.com"));

            assertThat(filter.resolveTenant(exchange)).isEqualTo("fromhost");
        }

        @Test
        void xTenantInvalidAndXForwardedHostValid_returnsTenantFromXForwardedHost() {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header(TenantDomainWebFilter.HEADER_X_TENANT, "1invalid")
                    .header(TenantDomainWebFilter.HEADER_X_FORWARDED_HOST, "fromforwarded.example.com")
                    .header("Host", "fromhost.example.com"));

            assertThat(filter.resolveTenant(exchange)).isEqualTo("fromforwarded");
        }

        @Test
        void xTenantBlank_usesXForwardedHost() {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header(TenantDomainWebFilter.HEADER_X_TENANT, "   ")
                    .header(TenantDomainWebFilter.HEADER_X_FORWARDED_HOST, "acme.example.com"));

            assertThat(filter.resolveTenant(exchange)).isEqualTo("acme");
        }

        @Test
        void xForwardedHostWithSubdomain_returnsTenant() {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header("Host", "alb.internal")
                    .header(TenantDomainWebFilter.HEADER_X_FORWARDED_HOST, "acme.example.com"));

            assertThat(filter.resolveTenant(exchange)).isEqualTo("acme");
        }

        @Test
        void xForwardedHostWithPort_stripsPort() {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header(TenantDomainWebFilter.HEADER_X_FORWARDED_HOST, "acme.example.com:443"));

            assertThat(filter.resolveTenant(exchange)).isEqualTo("acme");
        }

        @Test
        void xForwardedHostUppercase_normalisesToLowercase() {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header(TenantDomainWebFilter.HEADER_X_FORWARDED_HOST, "ACME.example.com"));

            assertThat(filter.resolveTenant(exchange)).isEqualTo("acme");
        }

        @Test
        void xForwardedHostWithoutDot_fallsBackToHost() {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header(TenantDomainWebFilter.HEADER_X_FORWARDED_HOST, "alb-internal")
                    .header("Host", "fromhost.example.com"));

            assertThat(filter.resolveTenant(exchange)).isEqualTo("fromhost");
        }

        @Test
        void xForwardedHostWithInvalidSubdomain_fallsBackToHost() {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header(TenantDomainWebFilter.HEADER_X_FORWARDED_HOST, "1invalid.example.com")
                    .header("Host", "fromhost.example.com"));

            assertThat(filter.resolveTenant(exchange)).isEqualTo("fromhost");
        }

        @Test
        void xForwardedHostBlank_fallsBackToHost() {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header(TenantDomainWebFilter.HEADER_X_FORWARDED_HOST, "   ")
                    .header("Host", "fromhost.example.com"));

            assertThat(filter.resolveTenant(exchange)).isEqualTo("fromhost");
        }

        @Test
        void xTenantAndXForwardedHostAbsent_usesHostHeader() {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header("Host", "acme.example.com"));

            assertThat(filter.resolveTenant(exchange)).isEqualTo("acme");
        }

        @Test
        void noValidTenantInAnySource_returnsNull() {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header(TenantDomainWebFilter.HEADER_X_TENANT, "1invalid")
                    .header(TenantDomainWebFilter.HEADER_X_FORWARDED_HOST, "alb-internal")
                    .header("Host", "localhost"));

            assertThat(filter.resolveTenant(exchange)).isNull();
        }
    }

    // -------------------------------------------------------------------------
    // Reactor context propagation
    // -------------------------------------------------------------------------

    @Nested
    class ReactorContextPropagation {

        private final TenantDomainWebFilter filter = new TenantDomainWebFilter(false);

        @Test
        void resolvedTenant_isWrittenToReactorContext() {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header("Host", "acme.example.com"));

            String[] captured = {null};

            filter.filter(exchange, ex ->
                    reactor.core.publisher.Mono.deferContextual(ctx -> {
                        captured[0] = ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, null);
                        return reactor.core.publisher.Mono.empty();
                    })
            ).block();

            assertThat(captured[0]).isEqualTo("acme");
        }

        @Test
        void unresolvableTenant_doesNotWriteContextKey() {
            var exchange = exchange(MockServerHttpRequest.get("/")
                    .header("Host", "localhost"));

            String[] captured = {"not-set"};

            filter.filter(exchange, ex ->
                    reactor.core.publisher.Mono.deferContextual(ctx -> {
                        captured[0] = ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, null);
                        return reactor.core.publisher.Mono.empty();
                    })
            ).block();

            assertThat(captured[0]).isNull();
        }
    }

    // -------------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------------

    private static MockServerWebExchange exchange(MockServerHttpRequest.BaseBuilder<?> builder) {
        return MockServerWebExchange.from(builder.build());
    }
}