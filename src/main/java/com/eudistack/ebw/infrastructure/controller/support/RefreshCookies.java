package com.eudistack.ebw.infrastructure.controller.support;

import com.eudistack.ebw.domain.model.exception.InvalidSessionException;
import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * The {@code __Host-wallet_refresh} cookie that carries the session's refresh token:
 * {@code HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=<seconds until the session's maximum
 * duration>}. The {@code __Host-} prefix makes the browser refuse it unless it is Secure, has
 * {@code Path=/} and no {@code Domain}, so no sibling host or path can set or shadow it. Never
 * readable by the Wallet App.
 */
@Component
public class RefreshCookies {

    public static final String NAME = "__Host-wallet_refresh";
    private static final String PATH = "/";

    public ResponseCookie issue(String refreshToken, Instant sessionExpiresAt) {
        var maxAge = Duration.between(Instant.now(), sessionExpiresAt);
        return base(refreshToken).maxAge(maxAge.isNegative() ? Duration.ZERO : maxAge).build();
    }

    public ResponseCookie clear() {
        return base("").maxAge(Duration.ZERO).build();
    }

    /**
     * Value of the refresh cookie of the request, or {@code null}.
     *
     * @throws InvalidSessionException the request carries more than one refresh cookie
     */
    public String read(ServerHttpRequest request) {
        List<HttpCookie> cookies = request.getCookies().get(NAME);
        if (cookies == null || cookies.isEmpty()) {
            return null;
        }
        if (cookies.size() > 1) {
            throw new InvalidSessionException();
        }
        var value = cookies.get(0).getValue();
        return value.isBlank() ? null : value;
    }

    private static ResponseCookie.ResponseCookieBuilder base(String value) {
        return ResponseCookie.from(NAME, value)
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path(PATH);
    }
}
