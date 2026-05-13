package com.eudistack.ebw.wallet.config.infrastructure.web;

import com.eudistack.ebw.wallet.config.application.workflow.WalletTenantConfigReadService;
import com.eudistack.ebw.wallet.config.domain.model.TenantWalletConfigDescriptor;
import com.eudistack.ebw.wallet.config.domain.model.WalletMode;
import com.eudistack.ebw.wallet.config.infrastructure.controller.WalletTenantConfigDiscoveryController;
import com.eudistack.ebw.wallet.config.infrastructure.controller.dto.DiscoveryResponseDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Collections;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Controller tests for {@link WalletTenantConfigDiscoveryController} — covers T-4 (tech-design §2.3).
 *
 * <p><strong>Why Mockito, not {@code @SpringBootTest}.</strong> {@code src/test/resources/application.yml}
 * excludes {@code R2dbcAutoConfiguration} / {@code R2dbcRepositoriesAutoConfiguration} /
 * {@code FlywayAutoConfiguration} so the {@code ApplicationTests.contextLoads()} smoke test can boot
 * without Postgres. A {@code @SpringBootTest} over this controller would therefore not get an R2DBC
 * stack. So the controller is exercised at the method level with a mocked
 * {@link WalletTenantConfigReadService}; the DB-level contract (CHECK constraints, migration) is
 * covered separately by {@code TenantWalletConfigSchemaMigrationIT} which spins up a real Postgres
 * via Testcontainers without a Spring context.
 *
 * <p>Covers: 200 with the 4-field projection (no {@code key_manager}/{@code activation_status}) +
 * headers {@code Cache-Control: public, max-age=60} / {@code ETag: "<version>"} / {@code Vary: Host}
 * (AC-1a, AC-1c, AC-1d); uppercase {@code Host} → 200 normalised (AC-1e, E-4); unregistered host →
 * opaque 404 RFC 9457, going through the same number of read-service calls as the 200 (AC-3a, AC-3b,
 * E-1); missing / blank {@code Host} → 400 RFC 9457 {@code urn:eudistack:error:missing-host-header}
 * with no port call (AC-4a, AC-4b, E-2, E-3).
 *
 * <p>Tagged {@code integration} per tech-design §2.3 (runs under {@code ./gradlew integrationTest}).
 */
@ExtendWith(MockitoExtension.class)
@Tag("integration")
class WalletTenantConfigDiscoveryControllerIT {

    private static final String HOST = "acme.eudiw.example.com";

    @Mock
    WalletTenantConfigReadService readService;

    WalletTenantConfigDiscoveryController controller;

    @BeforeEach
    void setUp() {
        controller = new WalletTenantConfigDiscoveryController(readService);
    }

    // ------------------------------------------------------------------
    // 200 — known browser tenant: 4-field projection + caching headers (AC-1a, AC-1c, AC-1d)
    // ------------------------------------------------------------------

    @Test
    void getBrowserTenant_returns200WithFourFieldProjectionAndCachingHeaders() {
        // Given
        TenantWalletConfigDescriptor descriptor = TenantWalletConfigDescriptor.of(
                "acme_business_wallet", HOST, WalletMode.BROWSER,
                Optional.empty(), false, Collections.emptyList(), 3L);
        when(readService.retrieveDescriptor(HOST)).thenReturn(Mono.just(descriptor));

        // When
        Mono<ResponseEntity<Object>> result = controller.discover(HOST);

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

                    HttpHeaders headers = response.getHeaders();
                    assertThat(headers.getCacheControl()).contains("max-age=60").contains("public");
                    assertThat(headers.getETag()).isEqualTo("\"3\"");
                    assertThat(headers.getVary()).containsExactly(HttpHeaders.HOST);

                    // 4-field projection: no key_manager, no activation_status (AD-1bis).
                    assertThat(response.getBody()).isInstanceOf(DiscoveryResponseDto.class);
                    DiscoveryResponseDto dto = (DiscoveryResponseDto) response.getBody();
                    assertThat(dto.walletMode()).isEqualTo("browser");
                    assertThat(dto.naturalPersonsOnly()).isFalse();
                    assertThat(dto.supportedCredentials()).isEmpty();
                    assertThat(dto.version()).isEqualTo(3L);
                })
                .verifyComplete();

        verify(readService, times(1)).retrieveDescriptor(HOST);
    }

    // ------------------------------------------------------------------
    // AC-1e / E-4 — uppercase Host (and Host with port) → normalised → 200
    // ------------------------------------------------------------------

    @Test
    void getBrowserTenant_uppercaseHost_isNormalisedToLowercaseAndReturns200() {
        // Given — the service is stubbed for the *lowercase* host only
        TenantWalletConfigDescriptor descriptor =
                TenantWalletConfigDescriptor.forBrowserTenant("acme_business_wallet", HOST);
        when(readService.retrieveDescriptor(HOST)).thenReturn(Mono.just(descriptor));

        // When — caller sends the uppercase variant
        Mono<ResponseEntity<Object>> result = controller.discover(HOST.toUpperCase());

        // Then — the controller lowercased it before the lookup, so the stub matched → 200
        StepVerifier.create(result)
                .assertNext(response -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK))
                .verifyComplete();

        verify(readService, times(1)).retrieveDescriptor(HOST);
    }

    // ------------------------------------------------------------------
    // AC-3a / AC-3b / E-1 — unregistered host → opaque 404, same #DB calls as the 200
    // ------------------------------------------------------------------

    @Test
    void getUnregisteredHost_returns404OpaqueRfc9457_throughSameNumberOfReadCallsAsThe200() {
        // Given
        String unknownHost = "unknown.eudiw.example.com";
        when(readService.retrieveDescriptor(unknownHost)).thenReturn(Mono.empty());

        // When
        Mono<ResponseEntity<Object>> result = controller.discover(unknownHost);

        // Then — opaque RFC 9457 body, no caching headers
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
                    assertThat(response.getHeaders().getCacheControl()).isNull();

                    assertThat(response.getBody()).isInstanceOf(ProblemDetail.class);
                    ProblemDetail problem = (ProblemDetail) response.getBody();
                    assertThat(problem.getType().toString()).isEqualTo("about:blank");
                    assertThat(problem.getTitle()).isEqualTo("Not Found");
                    assertThat(problem.getStatus()).isEqualTo(404);
                    // No cause discriminator — the body must not reveal whether the host exists.
                    assertThat(problem.getDetail()).isNull();
                })
                .verifyComplete();

        // AC-3b: the 404 path makes exactly one read-service call — the same as the 200 path.
        verify(readService, times(1)).retrieveDescriptor(unknownHost);
    }

    // ------------------------------------------------------------------
    // AC-4a / E-2 — missing Host header → 400, no port call
    // ------------------------------------------------------------------

    @Test
    void missingHostHeader_returns400Rfc9457_withoutTouchingThePort() {
        // Given: Spring maps an absent @RequestHeader(required=false) to null.
        // When
        Mono<ResponseEntity<Object>> result = controller.discover(null);

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

                    assertThat(response.getBody()).isInstanceOf(ProblemDetail.class);
                    ProblemDetail problem = (ProblemDetail) response.getBody();
                    assertThat(problem.getType().toString()).isEqualTo("urn:eudistack:error:missing-host-header");
                    assertThat(problem.getTitle()).isEqualTo("Missing Host header");
                    assertThat(problem.getStatus()).isEqualTo(400);
                    assertThat(problem.getDetail()).isEqualTo("A Host header is required to resolve the tenant");
                })
                .verifyComplete();

        verifyNoInteractions(readService);
    }

    // ------------------------------------------------------------------
    // AC-4b / E-3 — blank / whitespace-only Host header → 400, no port call
    // ------------------------------------------------------------------

    @Test
    void blankHostHeader_returns400Rfc9457_withoutTouchingThePort() {
        // When
        Mono<ResponseEntity<Object>> result = controller.discover("   ");

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
                    assertThat(response.getBody()).isInstanceOf(ProblemDetail.class);
                    ProblemDetail problem = (ProblemDetail) response.getBody();
                    assertThat(problem.getType().toString()).isEqualTo("urn:eudistack:error:missing-host-header");
                })
                .verifyComplete();

        verifyNoInteractions(readService);
    }
}
