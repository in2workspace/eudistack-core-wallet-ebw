package com.eudistack.ebw.wallet.profile.infrastructure.web;

import com.eudistack.ebw.infrastructure.configuration.TenantDomainWebFilter;
import com.eudistack.ebw.wallet.profile.infrastructure.observability.WalletProfileQueryTelemetry;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for the tenant extraction logic in {@link WellKnownCanonicalHandler}.
 *
 * <p>The handler runs at Reactor Netty routing level, before Spring WebFlux filters, so it
 * carries its own {@code extractTenant} implementation that must mirror
 * {@link TenantDomainWebFilter} exactly.
 *
 * <p>Covers both {@code trust-forwarded-host} modes in full parity with
 * {@code TenantDomainWebFilterTest}.
 */
@ExtendWith(MockitoExtension.class)
class WellKnownCanonicalHandlerTenantTest {

    @Mock
    private WalletProfileQueryController controller;
    @Mock
    private WalletProfileQueryTelemetry telemetry;

    private WellKnownCanonicalHandler handler(boolean trustForwardedHost) {
        return new WellKnownCanonicalHandler(controller, telemetry, new ObjectMapper(),
                trustForwardedHost);
    }

    // -------------------------------------------------------------------------
    // trust-forwarded-host = false (default)
    // -------------------------------------------------------------------------

    @Nested
    class TrustForwardedHostDisabled {

        private final WellKnownCanonicalHandler h = handler(false);

        @Test
        void hostWithSubdomain_returnsTenant() {
            assertThat(h.extractTenant(request("Host", "acme.example.com"))).isEqualTo("acme");
        }

        @Test
        void hostWithPort_stripsPort() {
            assertThat(h.extractTenant(request("Host", "acme.example.com:8443"))).isEqualTo("acme");
        }

        @Test
        void uppercaseHost_normalisesToLowercase() {
            assertThat(h.extractTenant(request("Host", "ACME.example.com"))).isEqualTo("acme");
        }

        @Test
        void hostWithoutDot_returnsNull() {
            assertThat(h.extractTenant(request("Host", "localhost"))).isNull();
        }

        @Test
        void hostWithLeadingDot_returnsNull() {
            assertThat(h.extractTenant(request("Host", ".example.com"))).isNull();
        }

        @ParameterizedTest
        @ValueSource(strings = {"1tenant.example.com", "-tenant.example.com"})
        void subdomainStartingWithNonLetter_returnsNull(String host) {
            assertThat(h.extractTenant(request("Host", host))).isNull();
        }

        @Test
        void xForwardedHostPresent_isIgnoredWhenTrustDisabled() {
            var req = MockServerHttpRequest.get("/")
                    .header("Host", "trustedhost.example.com")
                    .header(TenantDomainWebFilter.HEADER_X_FORWARDED_HOST, "other.example.com")
                    .build();
            assertThat(h.extractTenant(req)).isEqualTo("trustedhost");
        }

        @Test
        void xTenantPresent_isIgnoredWhenTrustDisabled() {
            var req = MockServerHttpRequest.get("/")
                    .header("Host", "fromhost.example.com")
                    .header(TenantDomainWebFilter.HEADER_X_TENANT, "fromheader")
                    .build();
            assertThat(h.extractTenant(req)).isEqualTo("fromhost");
        }
    }

    // -------------------------------------------------------------------------
    // trust-forwarded-host = true
    // -------------------------------------------------------------------------

    @Nested
    class TrustForwardedHostEnabled {

        private final WellKnownCanonicalHandler h = handler(true);

        @Test
        void xForwardedHostWithSubdomain_returnsTenant() {
            var req = MockServerHttpRequest.get("/")
                    .header("Host", "alb.internal")
                    .header(TenantDomainWebFilter.HEADER_X_FORWARDED_HOST, "acme.example.com")
                    .build();
            assertThat(h.extractTenant(req)).isEqualTo("acme");
        }

        @Test
        void xForwardedHostWithPort_stripsPort() {
            var req = MockServerHttpRequest.get("/")
                    .header(TenantDomainWebFilter.HEADER_X_FORWARDED_HOST, "acme.example.com:443")
                    .build();
            assertThat(h.extractTenant(req)).isEqualTo("acme");
        }

        @Test
        void xForwardedHostUppercase_normalisesToLowercase() {
            var req = MockServerHttpRequest.get("/")
                    .header(TenantDomainWebFilter.HEADER_X_FORWARDED_HOST, "ACME.example.com")
                    .build();
            assertThat(h.extractTenant(req)).isEqualTo("acme");
        }

        @Test
        void xForwardedHostWithoutDot_fallsBackToXTenant() {
            var req = MockServerHttpRequest.get("/")
                    .header(TenantDomainWebFilter.HEADER_X_FORWARDED_HOST, "alb-internal")
                    .header(TenantDomainWebFilter.HEADER_X_TENANT, "acme")
                    .build();
            assertThat(h.extractTenant(req)).isEqualTo("acme");
        }

        @Test
        void xForwardedHostWithInvalidSubdomain_fallsBackToXTenant() {
            var req = MockServerHttpRequest.get("/")
                    .header(TenantDomainWebFilter.HEADER_X_FORWARDED_HOST, "1invalid.example.com")
                    .header(TenantDomainWebFilter.HEADER_X_TENANT, "acme")
                    .build();
            assertThat(h.extractTenant(req)).isEqualTo("acme");
        }

        @Test
        void xForwardedHostAbsent_usesXTenantHeader() {
            var req = MockServerHttpRequest.get("/")
                    .header("Host", "alb.internal")
                    .header(TenantDomainWebFilter.HEADER_X_TENANT, "acme")
                    .build();
            assertThat(h.extractTenant(req)).isEqualTo("acme");
        }

        @Test
        void xForwardedHostBlank_usesXTenantHeader() {
            var req = MockServerHttpRequest.get("/")
                    .header(TenantDomainWebFilter.HEADER_X_FORWARDED_HOST, "   ")
                    .header(TenantDomainWebFilter.HEADER_X_TENANT, "acme")
                    .build();
            assertThat(h.extractTenant(req)).isEqualTo("acme");
        }

        @Test
        void xTenantUppercase_normalisesToLowercase() {
            var req = MockServerHttpRequest.get("/")
                    .header(TenantDomainWebFilter.HEADER_X_TENANT, "ACME")
                    .build();
            assertThat(h.extractTenant(req)).isEqualTo("acme");
        }

        @Test
        void xTenantWithLeadingTrailingSpaces_isTrimmedAndAccepted() {
            var req = MockServerHttpRequest.get("/")
                    .header(TenantDomainWebFilter.HEADER_X_TENANT, "  acme  ")
                    .build();
            assertThat(h.extractTenant(req)).isEqualTo("acme");
        }

        @ParameterizedTest
        @ValueSource(strings = {"1tenant", "-tenant", "tenant.with.dot", "tenant with space"})
        void xTenantWithInvalidFormat_returnsNull(String value) {
            var req = MockServerHttpRequest.get("/")
                    .header(TenantDomainWebFilter.HEADER_X_TENANT, value)
                    .build();
            assertThat(h.extractTenant(req)).isNull();
        }

        @Test
        void neitherXForwardedHostNorXTenant_returnsNull() {
            var req = MockServerHttpRequest.get("/")
                    .header("Host", "acme.example.com")
                    .build();
            assertThat(h.extractTenant(req)).isNull();
        }

        @Test
        void hostHeaderIsNotUsedAsFallback() {
            var req = MockServerHttpRequest.get("/")
                    .header("Host", "acme.example.com")
                    .build();
            assertThat(h.extractTenant(req)).isNull();
        }
    }

    // -------------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------------

    private static MockServerHttpRequest request(String headerName, String headerValue) {
        return MockServerHttpRequest.get("/").header(headerName, headerValue).build();
    }
}
