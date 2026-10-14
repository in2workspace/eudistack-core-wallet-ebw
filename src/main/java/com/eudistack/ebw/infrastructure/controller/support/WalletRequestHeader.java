package com.eudistack.ebw.infrastructure.controller.support;

import org.springframework.http.server.reactive.ServerHttpRequest;

/**
 * CSRF protection of the endpoints that use the refresh cookie (renewal, sign-out, and the
 * registration and sign-in that end the cookie's session): they require
 * {@code X-Wallet-Request: 1}. A cross-site form cannot send a custom header, and a cross-site
 * script needs a CORS preflight that only the configured origins pass.
 */
public final class WalletRequestHeader {

    public static final String NAME = "X-Wallet-Request";

    private WalletRequestHeader() {}

    public static void require(ServerHttpRequest request) {
        if (!"1".equals(request.getHeaders().getFirst(NAME))) {
            throw new MissingWalletRequestHeaderException();
        }
    }

    /** The request lacks {@code X-Wallet-Request: 1}: answered with 403 {@code forbidden}. */
    public static class MissingWalletRequestHeaderException extends RuntimeException {
        public MissingWalletRequestHeaderException() {
            super("Missing X-Wallet-Request header");
        }
    }
}
