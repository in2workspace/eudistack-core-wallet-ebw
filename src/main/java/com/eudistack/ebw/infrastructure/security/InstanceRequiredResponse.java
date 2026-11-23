package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.infrastructure.controller.support.AuthProblems;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * The 403 {@code instance_required} problem (EUD-15 AD-3): the session is alive but not bound to an active
 * Wallet Instance, and the route is not one of the {@link InstanceExemptRoutes}. The Wallet App binds the
 * session once and retries, or registers the device.
 */
public final class InstanceRequiredResponse {

    private InstanceRequiredResponse() {
    }

    public static Mono<Void> write(ServerWebExchange exchange, ObjectMapper objectMapper) {
        var response = exchange.getResponse();
        response.setStatusCode(HttpStatus.FORBIDDEN);
        response.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        byte[] body;
        try {
            body = objectMapper.writeValueAsBytes(AuthProblems.of(HttpStatus.FORBIDDEN, AuthProblems.INSTANCE_REQUIRED));
        } catch (Exception _) {
            body = new byte[0];
        }
        return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
    }
}
