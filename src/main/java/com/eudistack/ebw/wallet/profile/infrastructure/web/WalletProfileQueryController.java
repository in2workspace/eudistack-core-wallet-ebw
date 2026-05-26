package com.eudistack.ebw.wallet.profile.infrastructure.web;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.wallet.profile.infrastructure.observability.WalletProfileQueryTelemetry;
import com.eudistack.ebw.wallet.profile.infrastructure.web.dto.WalletConfigMetadataResponse;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * REST controller exposing the public wallet discovery endpoint.
 *
 * <p>Path: {@code GET /.well-known/wallet-config-metadata}
 *
 * <p>The canonical path {@code /.well-known/wallet-config-metadata} is served by
 * {@link WellKnownCanonicalHandler} at the Reactor Netty routing level, before the
 * {@code spring.webflux.base-path=/business-wallet} filter rejects non-prefixed requests
 * (AD-413-1 / RFC 8615). This controller handles the unit-test path only
 * ({@code WebTestClient.bindToController}) and provides the
 * {@link #WELL_KNOWN_PATH} constant consumed by the Netty route registration.
 *
 * <p>No authentication is required (AC-03). Security headers and cache headers are added
 * on the 200 success path here; error paths delegate to
 * {@link WalletProfileQueryExceptionHandler}.
 *
 * <p>See technical-design.md §3.2 and §3.5 AD-413-1, acceptance-criteria.md AC-01–AC-03/AC-06.
 */
@RestController
public class WalletProfileQueryController {

    static final String WELL_KNOWN_PATH = "/.well-known/wallet-config-metadata";
    private static final String HEADER_CACHE_CONTROL = "Cache-Control";
    private static final String HEADER_CACHE_CONTROL_VALUE = "public, max-age=60, must-revalidate";
    private static final String HEADER_X_CONTENT_TYPE_OPTIONS = "X-Content-Type-Options";
    private static final String HEADER_X_CONTENT_TYPE_OPTIONS_VALUE = "nosniff";
    private static final String HEADER_REFERRER_POLICY = "Referrer-Policy";
    private static final String HEADER_REFERRER_POLICY_VALUE = "no-referrer";

    private final WalletProfileQueryPort walletProfileQueryPort;
    private final WalletProfileQueryTelemetry telemetry;

    public WalletProfileQueryController(WalletProfileQueryPort walletProfileQueryPort,
                                        WalletProfileQueryTelemetry telemetry) {
        this.walletProfileQueryPort = walletProfileQueryPort;
        this.telemetry = telemetry;
    }

    /**
     * Returns the wallet discovery configuration for the current tenant.
     *
     * <p>The tenant is resolved implicitly from the Reactor Context set by
     * {@code TenantDomainWebFilter}. The response body is a {@link WalletConfigMetadataResponse}
     * JSON object with {@code wallet_mode} and, when applicable, {@code key_manager}.
     *
     * @return 200 with the discovery JSON + security and cache headers on success;
     *         error signals propagated to {@link WalletProfileQueryExceptionHandler}
     */
    @GetMapping(WELL_KNOWN_PATH)
    public Mono<ResponseEntity<WalletConfigMetadataResponse>> getWalletConfigMetadata() {
        long startNanos = System.nanoTime();
        return walletProfileQueryPort.queryByCurrentTenant()
                .flatMap(profile -> Mono.deferContextual(ctx -> {
                    String tenant = ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, "unknown");
                    telemetry.recordSuccess(tenant, startNanos);
                    WalletConfigMetadataResponse body = WalletConfigMetadataResponse.from(profile);
                    ResponseEntity<WalletConfigMetadataResponse> response =
                            ResponseEntity.status(HttpStatus.OK)
                                    .header(HEADER_CACHE_CONTROL, HEADER_CACHE_CONTROL_VALUE)
                                    .header(HEADER_X_CONTENT_TYPE_OPTIONS,
                                            HEADER_X_CONTENT_TYPE_OPTIONS_VALUE)
                                    .header(HEADER_REFERRER_POLICY, HEADER_REFERRER_POLICY_VALUE)
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .body(body);
                    return Mono.just(response);
                }));
    }
}
