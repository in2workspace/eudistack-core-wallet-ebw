package com.eudistack.ebw.infrastructure.controller.support;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;

/**
 * The {@code wallet_refresh} cookie that carries the session's refresh token:
 * {@code HttpOnly; Secure; SameSite=Strict; Path=<base-path>/api/v1/auth;
 * Max-Age=<seconds until the session's maximum duration>}. Never readable by the Wallet App.
 */
@Component
public class RefreshCookies {

    public static final String NAME = "wallet_refresh";

    private final String path;

    public RefreshCookies(@Value("${spring.webflux.base-path:}") String basePath) {
        var prefix = basePath == null ? "" : basePath.replaceAll("/+$", "");
        this.path = prefix + "/api/v1/auth";
    }

    public ResponseCookie issue(String refreshToken, Instant sessionExpiresAt) {
        var maxAge = Duration.between(Instant.now(), sessionExpiresAt);
        return base(refreshToken).maxAge(maxAge.isNegative() ? Duration.ZERO : maxAge).build();
    }

    public ResponseCookie clear() {
        return base("").maxAge(Duration.ZERO).build();
    }

    /** Value of the refresh cookie of the request, or {@code null}. */
    public String read(ServerHttpRequest request) {
        HttpCookie cookie = request.getCookies().getFirst(NAME);
        return cookie == null || cookie.getValue().isBlank() ? null : cookie.getValue();
    }

    public String path() {
        return path;
    }

    private ResponseCookie.ResponseCookieBuilder base(String value) {
        return ResponseCookie.from(NAME, value)
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path(path);
    }
}
