package com.eudistack.ebw.infrastructure.controller.support;

import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;

/** Reads the registration ticket sent as {@code Authorization: Bearer <ticket>}. */
public final class BearerTickets {

    private static final String BEARER_PREFIX = "Bearer ";

    private BearerTickets() {}

    /** The ticket, or {@code null} when the request carries no bearer. */
    public static String read(ServerHttpRequest request) {
        var header = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            return null;
        }
        var value = header.substring(BEARER_PREFIX.length()).trim();
        return value.isEmpty() ? null : value;
    }
}
