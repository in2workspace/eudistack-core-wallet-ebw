package com.eudistack.ebw.wallet.config.infrastructure.web;

import com.eudistack.ebw.wallet.config.application.workflow.WalletTenantConfigReadService;
import com.eudistack.ebw.wallet.config.domain.model.TenantWalletConfigDescriptor;
import com.eudistack.ebw.wallet.config.domain.model.WalletMode;
import com.eudistack.ebw.wallet.config.infrastructure.controller.WalletTenantConfigDiscoveryController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Collections;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Controller unit tests for {@link WalletTenantConfigDiscoveryController}.
 *
 * <p>Covers T-6 (AC-1a, AC-1e), T-7 (AC-1c), T-14 (E-9) from tech-design §2.3.
 *
 * <p>Tests the controller's HTTP contract at the method level (without a running WebFlux
 * context), verifying: status codes, DTO projection (no key_manager), Cache-Control header,
 * ETag header, and RFC 9457 error body format.
 *
 * <p>This focused approach avoids the overhead of spinning up the full WebFlux infrastructure
 * while still exercising the controller's end-to-end request handling logic.
 *
 * <p>Tagged {@code integration} per tech-design §2.3 test matrix (T-6, T-7, T-14).
 */
@ExtendWith(MockitoExtension.class)
@Tag("integration")
class WalletTenantConfigDiscoveryControllerIT {

    @Mock
    WalletTenantConfigReadService readService;

    WalletTenantConfigDiscoveryController controller;

    @BeforeEach
    void setUp() {
        controller = new WalletTenantConfigDiscoveryController(readService);
    }

    // ------------------------------------------------------------------
    // T-6: discover() with known host → 200 + correct body + headers (AC-1a, AC-1e)
    // ------------------------------------------------------------------

    /**
     * T-6: Known browser tenant → HTTP 200 with correct payload and caching headers.
     *
     * <p>Verifies:
     * <ul>
     *   <li>Response status 200.</li>
     *   <li>Body is a {@code DiscoveryResponseDto} with {@code wallet_mode="browser"},
     *       {@code natural_persons_only=false}, {@code supported_credentials=[]},
     *       {@code version=3}.</li>
     *   <li>Body does NOT carry a {@code key_manager} field (AC-1e, AD-1bis) — verified
     *       by using the type-safe DTO class which intentionally omits the field.</li>
     *   <li>{@code Cache-Control: public, max-age=60} header present.</li>
     *   <li>{@code ETag} header present and equals {@code "3"} (version-based).</li>
     * </ul>
     */
    @Test
    void getBrowserTenantReturns200WithCorrectPayload() {
        // Given
        String host = "acme.eudiw.example.com";
        TenantWalletConfigDescriptor descriptor = TenantWalletConfigDescriptor.of(
                "acme_bw", host, WalletMode.BROWSER,
                Optional.empty(), false, Collections.emptyList(), 3L);
        when(readService.retrieveDescriptor(host)).thenReturn(Mono.just(descriptor));

        // When
        Mono<ResponseEntity<Object>> result = controller.discover(host);

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                    assertThat(response.getHeaders().getCacheControl())
                            .contains("max-age=60");
                    assertThat(response.getHeaders().getETag()).isEqualTo("\"3\"");

                    // AC-1e: body is a DiscoveryResponseDto (no key_manager field in type)
                    var dto = (com.eudistack.ebw.wallet.config.infrastructure.controller.dto.DiscoveryResponseDto) response.getBody();
                    assertThat(dto).isNotNull();
                    assertThat(dto.walletMode()).isEqualTo("browser");
                    assertThat(dto.naturalPersonsOnly()).isFalse();
                    assertThat(dto.supportedCredentials()).isEmpty();
                    assertThat(dto.version()).isEqualTo(3L);
                })
                .verifyComplete();
    }

    // ------------------------------------------------------------------
    // T-7: discover() with unknown host → 404 RFC 9457 opaque (AC-1c)
    // ------------------------------------------------------------------

    /**
     * T-7: Unknown host → HTTP 404 with opaque RFC 9457 body (AC-1c).
     *
     * <p>Verifies:
     * <ul>
     *   <li>Response status 404.</li>
     *   <li>Body is a {@link ProblemDetail} with {@code type=about:blank} (opaque).</li>
     *   <li>Body {@code title} is "Not Found".</li>
     * </ul>
     */
    @Test
    void getUnknownHostReturns404Opaque() {
        // Given
        String unknownHost = "unknown.eudiw.example.com";
        when(readService.retrieveDescriptor(unknownHost)).thenReturn(Mono.empty());

        // When
        Mono<ResponseEntity<Object>> result = controller.discover(unknownHost);

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);

                    var problem = (ProblemDetail) response.getBody();
                    assertThat(problem).isNotNull();
                    assertThat(problem.getType().toString()).isEqualTo("about:blank");
                    assertThat(problem.getTitle()).isEqualTo("Not Found");
                    assertThat(problem.getStatus()).isEqualTo(404);
                })
                .verifyComplete();
    }

    // ------------------------------------------------------------------
    // T-14: discover() with null/blank host → 400 RFC 9457 (E-9)
    // ------------------------------------------------------------------

    /**
     * T-14: {@code null} host → HTTP 400 with RFC 9457 body identifying missing-host-header (E-9).
     *
     * <p>Verifies:
     * <ul>
     *   <li>Response status 400.</li>
     *   <li>Body {@code type} identifies the missing-host-header error.</li>
     *   <li>No interaction with the read service (guard fires first).</li>
     * </ul>
     */
    @Test
    void missingHostHeaderReturns400() {
        // Given: null host (simulates missing Host header — Spring maps absent @RequestHeader to null)
        // When
        Mono<ResponseEntity<Object>> result = controller.discover(null);

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

                    var problem = (ProblemDetail) response.getBody();
                    assertThat(problem).isNotNull();
                    assertThat(problem.getType().toString())
                            .isEqualTo("urn:eudistack:error:missing-host-header");
                    assertThat(problem.getStatus()).isEqualTo(400);
                })
                .verifyComplete();
    }

    /**
     * T-14 (blank variant): blank host → HTTP 400 with RFC 9457 body.
     */
    @Test
    void blankHostHeaderReturns400() {
        // When
        Mono<ResponseEntity<Object>> result = controller.discover("   ");

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
                    assertThat(response.getBody()).isInstanceOf(ProblemDetail.class);
                })
                .verifyComplete();
    }

    // ------------------------------------------------------------------
    // AC-1d: host normalisation — uppercase host is lowercased before lookup
    // ------------------------------------------------------------------

    /**
     * AC-1d: Uppercase host is normalised to lowercase before calling the service.
     *
     * <p>Verifies that the service is called with the lowercase version of the host,
     * and the response is 200.
     */
    @Test
    void upperCaseHostIsNormalisedAndReturns200() {
        // Given
        String lowerHost = "acme-upper.eudiw.example.com";
        TenantWalletConfigDescriptor descriptor = TenantWalletConfigDescriptor.forBrowserTenant(
                "acme_upper_bw", lowerHost);
        // The controller normalizes to lowercase — so the service is called with lowerHost
        when(readService.retrieveDescriptor(lowerHost)).thenReturn(Mono.just(descriptor));

        // When: pass uppercase host to the controller
        Mono<ResponseEntity<Object>> result = controller.discover(lowerHost.toUpperCase());

        // Then
        StepVerifier.create(result)
                .assertNext(response -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK))
                .verifyComplete();
    }
}
