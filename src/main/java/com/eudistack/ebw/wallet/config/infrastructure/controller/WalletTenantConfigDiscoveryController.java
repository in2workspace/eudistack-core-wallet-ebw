package com.eudistack.ebw.wallet.config.infrastructure.controller;

import com.eudistack.ebw.wallet.config.application.workflow.WalletTenantConfigReadService;
import com.eudistack.ebw.wallet.config.infrastructure.controller.dto.DiscoveryResponseDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.concurrent.TimeUnit;

/**
 * Public discovery endpoint for the wallet tenant configuration plane.
 *
 * <p>Clients (EUDIW browser wallet) call this endpoint on bootstrap to discover
 * the {@code wallet_mode} for their host. The response is publicly cacheable via
 * CloudFront with a TTL of 60 seconds.
 *
 * <p>This controller has no authentication requirement — the path
 * {@code /.well-known/wallet-tenant-config} is added to the {@code permitAll()}
 * list in {@link com.eudistack.ebw.infrastructure.configuration.SecurityConfig}.
 *
 * <p>Security invariant (AD-1, AD-S2): this controller MUST NOT depend on
 * {@code TenantAwareConnectionFactoryDecorator} or any component that reads from
 * a tenant schema. The only persistence path flows through
 * {@code WalletTenantConfigReadService} → {@code TenantConfigurationPort} →
 * {@code WalletTenantConfigR2dbcAdapter} (publicSchema pool, search_path=public).
 * ArchUnit rule T-12 enforces this at compile time.
 */
@RestController
@RequestMapping("/.well-known/wallet-tenant-config")
public class WalletTenantConfigDiscoveryController {

    private static final Logger log = LoggerFactory.getLogger(WalletTenantConfigDiscoveryController.class);

    private static final String CACHE_CONTROL_VALUE =
            CacheControl.maxAge(60, TimeUnit.SECONDS).cachePublic().getHeaderValue();

    private final WalletTenantConfigReadService readService;

    public WalletTenantConfigDiscoveryController(WalletTenantConfigReadService readService) {
        this.readService = readService;
    }

    /**
     * Returns the public wallet tenant configuration for the host identified
     * by the {@code Host} request header.
     *
     * <ul>
     *   <li>HTTP 200 — tenant found; body is a {@link DiscoveryResponseDto} (no {@code key_manager});
     *       headers {@code Cache-Control: public, max-age=60}, {@code ETag: "<version>"}, {@code Vary: Host}.</li>
     *   <li>HTTP 400 — {@code Host} header absent or blank (E-2, E-3).</li>
     *   <li>HTTP 404 — host not registered; opaque RFC 9457 body (AC-3a, E-1).</li>
     * </ul>
     *
     * @param host the value of the HTTP {@code Host} header
     * @return a reactive response entity
     */
    @GetMapping
    public Mono<ResponseEntity<Object>> discover(
            @RequestHeader(value = HttpHeaders.HOST, required = false) String host) {

        if (host == null || host.isBlank()) {
            log.debug("Discovery request rejected: missing Host header");
            return Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .<Object>body(missingHostProblem()));
        }

        String normalizedHost = host.toLowerCase();
        log.debug("Discovery request for host={}", normalizedHost);

        Mono<ResponseEntity<Object>> found = readService.retrieveDescriptor(normalizedHost)
                .map(descriptor -> {
                    DiscoveryResponseDto dto = DiscoveryResponseDto.from(descriptor);
                    String etag = "\"" + descriptor.getVersion() + "\"";
                    return ResponseEntity.ok()
                            .header(HttpHeaders.CACHE_CONTROL, CACHE_CONTROL_VALUE)
                            .header(HttpHeaders.ETAG, etag)
                            .header(HttpHeaders.VARY, HttpHeaders.HOST)
                            .<Object>body(dto);
                });

        Mono<ResponseEntity<Object>> notFound = Mono.fromSupplier(() -> {
            log.debug("Tenant not found for host={}", normalizedHost);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).<Object>body(opaqueNotFoundProblem());
        });

        return found.switchIfEmpty(notFound);
    }

    private static ProblemDetail missingHostProblem() {
        // RFC 9457 body, matching AC-4a exactly.
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        problem.setType(URI.create("urn:eudistack:error:missing-host-header"));
        problem.setTitle("Missing Host header");
        problem.setDetail("A Host header is required to resolve the tenant");
        return problem;
    }

    private static ProblemDetail opaqueNotFoundProblem() {
        // Intentionally opaque (AC-1c): does not reveal whether the host
        // exists anywhere in the system. Body follows RFC 9457 about:blank pattern.
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.NOT_FOUND);
        problem.setType(URI.create("about:blank"));
        problem.setTitle("Not Found");
        return problem;
    }
}
