package com.eudistack.ebw.wallet.profile.infrastructure.web;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

/**
 * WebFlux routing configuration for the public wallet discovery endpoint.
 *
 * <p>The path {@code /.well-known/wallet-config-metadata} must be accessible
 * <em>outside</em> the {@code webflux.base-path=/business-wallet} prefix (AD-413-1 /
 * RFC 8615). Spring WebFlux applies the {@code base-path} prefix to all
 * {@code @RequestMapping}-annotated controllers — to bypass this, the canonical path is
 * registered via a {@link RouterFunction} with {@link Ordered#HIGHEST_PRECEDENCE} that
 * routes the request directly to the {@link WalletProfileQueryController}.
 *
 * <p>HEAD requests are handled automatically by Spring WebFlux when a GET route is present
 * (EC-04).
 *
 * <p>See technical-design.md §3.5 AD-413-1 and acceptance-criteria.md AC-01/AC-03.
 */
@Configuration
public class WalletProfileQueryWebConfig {

    /**
     * Registers the well-known discovery path outside the application base-path.
     *
     * <p>The {@link RouterFunction} runs with the highest precedence so it intercepts
     * requests for {@code /.well-known/wallet-config-metadata} before Spring MVC/WebFlux
     * applies the {@code /business-wallet} context prefix. The handler delegates to
     * {@link WalletProfileQueryController#getWalletConfigMetadata()} and converts the
     * returned {@link org.springframework.http.ResponseEntity} to a
     * {@link ServerResponse}, preserving all headers set by the controller and the
     * exception handler.
     *
     * @param controller the query controller, injected by Spring
     * @return the functional router bean
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public RouterFunction<ServerResponse> walletConfigMetadataRouter(
            WalletProfileQueryController controller) {
        return RouterFunctions.route()
                .GET(WalletProfileQueryController.WELL_KNOWN_PATH,
                        request -> controller.getWalletConfigMetadata()
                                .flatMap(responseEntity -> {
                                    ServerResponse.BodyBuilder builder =
                                            ServerResponse.status(responseEntity.getStatusCode());
                                    responseEntity.getHeaders().forEach(
                                            (name, values) -> values.forEach(
                                                    value -> builder.header(name, value)));
                                    if (responseEntity.getBody() != null) {
                                        return builder.bodyValue(responseEntity.getBody());
                                    }
                                    return builder.build();
                                }))
                .build();
    }
}
