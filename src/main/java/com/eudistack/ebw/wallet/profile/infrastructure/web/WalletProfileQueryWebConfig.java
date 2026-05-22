package com.eudistack.ebw.wallet.profile.infrastructure.web;

import com.eudistack.ebw.wallet.profile.domain.exception.TenantUnknownException;
import io.r2dbc.spi.R2dbcException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.ResponseEntity;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.reactive.function.server.support.RouterFunctionMapping;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * WebFlux routing configuration for the public wallet discovery endpoint.
 *
 * <p>The path {@code /.well-known/wallet-config-metadata} must be accessible
 * <em>outside</em> the {@code webflux.base-path=/business-wallet} prefix (AD-413-1 /
 * RFC 8615). In Spring Boot 3.4+, {@code spring.webflux.base-path} is applied to the
 * {@code @Primary RouterFunctionMapping} that Boot auto-configures, which means a
 * {@code @Bean RouterFunction<ServerResponse>} registered with
 * {@code @Order(HIGHEST_PRECEDENCE)} still inherits the prefix through that mapping.
 * To bypass this, we register a named {@link RouterFunctionMapping} bean directly —
 * Spring Boot only modifies the {@code @Primary} mapping it creates; custom named beans
 * are untouched and register routes at their literal paths.
 *
 * <p>The same mapping also explicitly shadows the prefixed path
 * {@code /business-wallet/.well-known/wallet-config-metadata} with an HTTP 404 so the
 * route that {@link WalletProfileQueryController} gains via
 * {@code RequestMappingHandlerMapping} + {@code base-path} is never reachable from
 * outside, preserving RFC 8615 semantics.
 *
 * <p>Exception handling is performed inline via {@code onErrorResume} chains because
 * {@link org.springframework.web.bind.annotation.RestControllerAdvice} only fires for
 * annotated-controller dispatch through {@code RequestMappingHandlerAdapter}, not for
 * functional handler routes served by this mapping.
 *
 * <p>HEAD requests on the canonical path are handled automatically by Spring WebFlux
 * when a GET route is present (EC-04).
 *
 * <p>See technical-design.md §3.5 AD-413-1 and acceptance-criteria.md AC-01/AC-03.
 */
@Configuration
public class WalletProfileQueryWebConfig {

    /**
     * Registers a standalone {@link RouterFunctionMapping} that is NOT modified by
     * Spring Boot's {@code base-path} auto-configuration.
     *
     * <p>Two routes are registered:
     * <ol>
     *   <li>{@code GET /.well-known/wallet-config-metadata} — canonical RFC 8615 path,
     *       delegates to {@link WalletProfileQueryController} with inline exception handling.
     *   <li>{@code GET /business-wallet/.well-known/wallet-config-metadata} — shadow route
     *       that returns 404, blocking the {@code RequestMappingHandlerMapping} registration
     *       that the controller gains via {@code webflux.base-path}.
     * </ol>
     *
     * @param controller      the query controller
     * @param exceptionHandler the exception handler, called inline for all error paths
     * @return a fully-configured {@link RouterFunctionMapping} at {@link Ordered#HIGHEST_PRECEDENCE}
     */
    @Bean
    public RouterFunctionMapping wellKnownRouterFunctionMapping(
            WalletProfileQueryController controller,
            WalletProfileQueryExceptionHandler exceptionHandler) {

        RouterFunction<ServerResponse> routerFunction = RouterFunctions.route()
                .GET(WalletProfileQueryController.WELL_KNOWN_PATH, request -> {
                    request.attributes().put(
                            WalletProfileQueryExceptionHandler.ATTR_START_NANOS,
                            System.nanoTime());
                    ServerWebExchange exchange = request.exchange();
                    return controller.getWalletConfigMetadata()
                            .flatMap(this::toServerResponse)
                            .onErrorResume(TenantUnknownException.class, ex ->
                                    toServerResponse(exceptionHandler.handleTenantUnknown(ex, exchange)))
                            .onErrorResume(R2dbcException.class, ex ->
                                    toServerResponse(exceptionHandler.handleR2dbcException(ex, exchange)))
                            .onErrorResume(IllegalArgumentException.class, ex ->
                                    toServerResponse(exceptionHandler.handleIllegalArgument(ex, exchange)))
                            .onErrorResume(ex ->
                                    toServerResponse(exceptionHandler.handleThrowable(ex, exchange)));
                })
                // Shadow the base-path prefixed registration so it is never reachable.
                .GET("/business-wallet" + WalletProfileQueryController.WELL_KNOWN_PATH,
                        request -> ServerResponse.notFound().build())
                .build();

        RouterFunctionMapping mapping = new RouterFunctionMapping(routerFunction);
        mapping.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return mapping;
    }

    private Mono<ServerResponse> toServerResponse(ResponseEntity<?> re) {
        ServerResponse.BodyBuilder builder = ServerResponse.status(re.getStatusCode());
        re.getHeaders().forEach((name, values) -> values.forEach(v -> builder.header(name, v)));
        return re.hasBody() ? builder.bodyValue(re.getBody()) : builder.build();
    }
}
