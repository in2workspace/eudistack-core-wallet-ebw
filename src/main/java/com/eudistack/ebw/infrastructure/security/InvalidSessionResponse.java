package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.infrastructure.controller.support.AuthProblems;
import com.eudistack.ebw.infrastructure.controller.support.RefreshCookies;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * The contract's 401 {@code invalid_session} problem, shared by {@link JwtAuthenticationWebFilter}
 * (an access token whose session ended) and the security entry point (no valid access token on a
 * session endpoint). On the session endpoints it also clears the refresh cookie.
 */
public final class InvalidSessionResponse {

    /** Session endpoints: their {@code invalid_session} also clears the refresh cookie. */
    static final String SESSIONS_PATH = "/api/v1/auth/sessions/"; // NOSONAR java:S1075

    private InvalidSessionResponse() {
    }

    public static boolean isSessionEndpoint(ServerWebExchange exchange) {
        return exchange.getRequest().getPath().pathWithinApplication().value().startsWith(SESSIONS_PATH);
    }

    public static Mono<Void> write(ServerWebExchange exchange, ObjectMapper objectMapper,
                                   RefreshCookies refreshCookies) {
        var response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        if (isSessionEndpoint(exchange)) {
            response.getHeaders().add(HttpHeaders.SET_COOKIE, refreshCookies.clear().toString());
        }
        byte[] body;
        try {
            body = objectMapper.writeValueAsBytes(AuthProblems.of(HttpStatus.UNAUTHORIZED, AuthProblems.INVALID_SESSION));
        } catch (Exception _) {
            body = new byte[0];
        }
        return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
    }
}
