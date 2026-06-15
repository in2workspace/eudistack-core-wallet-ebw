package com.eudistack.ebw.wallet.profile.infrastructure.web;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.infrastructure.configuration.TenantDomainWebFilter;
import com.eudistack.ebw.wallet.profile.domain.exception.TenantUnknownException;
import com.eudistack.ebw.wallet.profile.infrastructure.observability.WalletProfileQueryTelemetry;
import com.eudistack.ebw.wallet.profile.infrastructure.web.dto.ErrorResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.r2dbc.spi.R2dbcException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.util.regex.Pattern;

/**
 * {@link HttpHandler} that serves {@code GET /.well-known/wallet-config-metadata} at the
 * Reactor Netty routing level, before the {@code spring.webflux.base-path=/business-wallet}
 * filter is applied (AD-413-1 / RFC 8615).
 *
 * <p>Spring Boot 3.5 wraps the entire Spring WebFlux handler chain in a
 * {@code ContextPathCompositeHandler} when {@code spring.webflux.base-path} is set.
 * Requests whose paths do not start with the base-path are rejected at the Reactor Netty
 * routing layer — before any {@code WebFilter} runs. To serve the RFC 8615 canonical path
 * without the {@code /business-wallet} prefix, a
 * {@link org.springframework.boot.web.embedded.netty.NettyRouteProvider} (registered by
 * {@link WellKnownNettyRouteCustomizer}) intercepts the path first and delegates here via
 * {@link org.springframework.http.server.reactive.ReactorHttpHandlerAdapter}.
 *
 * <p>Tenant resolution, error handling, and telemetry mirror the
 * {@link WalletProfileQueryExceptionHandler} contract byte-for-byte (AD-413-2):
 * the opaque 404 body and security/cache headers are identical on all three
 * anti-enumeration paths (AC-04 / AC-05 / AC-08).
 *
 * <p>HEAD requests receive all response headers but an empty body (EC-04).
 *
 * <p>See technical-design.md §3.5 AD-413-1 and acceptance-criteria.md
 * AC-01–AC-03 / AC-06 / EC-04.
 */
@Component
public class WellKnownCanonicalHandler {

    static final String HEADER_X_FORWARDED_HOST = TenantDomainWebFilter.HEADER_X_FORWARDED_HOST;
    static final String HEADER_X_TENANT = TenantDomainWebFilter.HEADER_X_TENANT;

    private static final Pattern VALID_TENANT = Pattern.compile("^[a-zA-Z][a-zA-Z0-9_-]*$");
    private static final String HEADER_CACHE_CONTROL = "Cache-Control";
    private static final String HEADER_CACHE_CONTROL_VALUE = "public, max-age=60, must-revalidate";
    private static final String HEADER_X_CONTENT_TYPE_OPTIONS = "X-Content-Type-Options";
    private static final String HEADER_X_CONTENT_TYPE_OPTIONS_VALUE = "nosniff";
    private static final String HEADER_REFERRER_POLICY = "Referrer-Policy";
    private static final String HEADER_REFERRER_POLICY_VALUE = "no-referrer";

    private final WalletProfileQueryController controller;
    private final WalletProfileQueryTelemetry telemetry;
    private final ObjectMapper objectMapper;
    private final boolean trustForwardedHost;

    public WellKnownCanonicalHandler(
            WalletProfileQueryController controller,
            WalletProfileQueryTelemetry telemetry,
            ObjectMapper objectMapper,
            @Value("${ebw.security.trust-forwarded-host:false}") boolean trustForwardedHost) {
        this.controller = controller;
        this.telemetry = telemetry;
        this.objectMapper = objectMapper;
        this.trustForwardedHost = trustForwardedHost;
    }

    /** Prefixed path added by CloudFront viewer-request function so the ALB rule /business-wallet/* matches. */
    private static final String WELL_KNOWN_PATH_PREFIXED =
            "/business-wallet" + WalletProfileQueryController.WELL_KNOWN_PATH;

    public Mono<Void> handle(ServerHttpRequest request, ServerHttpResponse response) {
        // Accept both the canonical RFC 8615 path and the /business-wallet/-prefixed variant
        // rewritten by the CloudFront viewer-request function (EUDISTACK-412 / STG routing).
        // Reject any other suffix-matched path.
        String path = request.getPath().value();
        if (!WalletProfileQueryController.WELL_KNOWN_PATH.equals(path)
                && !WELL_KNOWN_PATH_PREFIXED.equals(path)) {
            response.setStatusCode(HttpStatus.NOT_FOUND);
            return response.setComplete();
        }

        long startNanos = System.nanoTime();
        boolean headOnly = HttpMethod.HEAD.equals(request.getMethod());
        String tenant = extractTenant(request);

        return controller.getWalletConfigMetadata()
                .flatMap(re -> writeResponse(response, re, headOnly))
                .onErrorResume(TenantUnknownException.class, ex -> {
                    telemetry.recordNotFound(
                            tenant != null ? tenant : "unknown", ex.getReason(), startNanos);
                    return writeErrorResponse(response, HttpStatus.NOT_FOUND,
                            ErrorResponse.TENANT_UNKNOWN);
                })
                .onErrorResume(R2dbcException.class, ex -> {
                    telemetry.recordError("unknown", ex, startNanos);
                    return writeErrorResponse(response, HttpStatus.SERVICE_UNAVAILABLE,
                            ErrorResponse.SERVICE_UNAVAILABLE);
                })
                .onErrorResume(IllegalArgumentException.class, ex -> {
                    telemetry.recordError("unknown", ex, startNanos);
                    return writeErrorResponse(response, HttpStatus.INTERNAL_SERVER_ERROR,
                            ErrorResponse.INTERNAL_ERROR);
                })
                .onErrorResume(ex -> {
                    telemetry.recordError("unknown", ex, startNanos);
                    return writeErrorResponse(response, HttpStatus.INTERNAL_SERVER_ERROR,
                            ErrorResponse.INTERNAL_ERROR);
                })
                .contextWrite(ctx -> tenant != null
                        ? ctx.put(ReactorContextKeys.TENANT_DOMAIN, tenant)
                        : ctx);
    }

    private Mono<Void> writeResponse(ServerHttpResponse response, ResponseEntity<?> re,
                                     boolean headOnly) {
        response.setStatusCode(re.getStatusCode());
        re.getHeaders().forEach((name, values) ->
                values.forEach(v -> response.getHeaders().add(name, v)));

        byte[] json = null;
        if (re.hasBody()) {
            try {
                json = objectMapper.writeValueAsBytes(re.getBody());
            } catch (JsonProcessingException e) {
                return Mono.error(e);
            }
        }

        if (headOnly) {
            // Set Content-Length so Reactor Netty does not use Transfer-Encoding: chunked,
            // which would leave the client waiting for a terminal chunk that never arrives.
            response.getHeaders().setContentLength(json != null ? json.length : 0);
            return response.setComplete();
        }

        if (json == null) {
            return response.setComplete();
        }
        DataBuffer buffer = response.bufferFactory().wrap(json);
        return response.writeWith(Mono.just(buffer));
    }

    private Mono<Void> writeErrorResponse(ServerHttpResponse response, HttpStatus status,
                                           ErrorResponse errorBody) {
        ResponseEntity<ErrorResponse> re = ResponseEntity.status(status)
                .header(HEADER_CACHE_CONTROL, HEADER_CACHE_CONTROL_VALUE)
                .header(HEADER_X_CONTENT_TYPE_OPTIONS, HEADER_X_CONTENT_TYPE_OPTIONS_VALUE)
                .header(HEADER_REFERRER_POLICY, HEADER_REFERRER_POLICY_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .body(errorBody);
        return writeResponse(response, re, false);
    }

    String extractTenant(ServerHttpRequest request) {
        if (trustForwardedHost) {
            String fwdHost = request.getHeaders().getFirst(HEADER_X_FORWARDED_HOST);
            if (fwdHost != null && !fwdHost.isBlank()) {
                String tenant = subdomainOf(fwdHost);
                if (tenant != null) return tenant;
            }
            String xTenant = request.getHeaders().getFirst(HEADER_X_TENANT);
            if (xTenant != null && !xTenant.isBlank()) {
                String candidate = xTenant.trim().toLowerCase();
                return VALID_TENANT.matcher(candidate).matches() ? candidate : null;
            }
            return null;
        }
        InetSocketAddress addr = request.getHeaders().getHost();
        return addr != null ? subdomainOf(addr.getHostString()) : null;
    }

    private String subdomainOf(String host) {
        if (host == null || host.isBlank()) return null;
        String hostname = host.contains(":") ? host.substring(0, host.indexOf(':')) : host;
        int dotIndex = hostname.indexOf('.');
        if (dotIndex <= 0) return null;
        String candidate = hostname.substring(0, dotIndex).toLowerCase();
        return VALID_TENANT.matcher(candidate).matches() ? candidate : null;
    }
}
