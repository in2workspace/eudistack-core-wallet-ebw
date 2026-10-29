package com.eudistack.ebw.infrastructure.controller.support;

import com.eudistack.ebw.domain.model.exception.InvalidSessionException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpCookie;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Unit tests for {@link RefreshCookies}. */
class RefreshCookiesTest {

    private final RefreshCookies cookies = new RefreshCookies();

    @Test
    void issue_session_isAHostPrefixedHttpOnlyStrictCookieUntilTheSessionMaximum() {
        // Act
        var cookie = cookies.issue("token", Instant.now().plus(Duration.ofHours(8)));

        // Assert
        assertThat(cookie.getName()).isEqualTo("__Host-wallet_refresh");
        assertThat(cookie.getValue()).isEqualTo("token");
        assertThat(cookie.isHttpOnly()).isTrue();
        assertThat(cookie.isSecure()).isTrue();
        assertThat(cookie.getSameSite()).isEqualTo("Strict");
        assertThat(cookie.getPath()).isEqualTo("/");
        assertThat(cookie.getDomain()).isNull();
        assertThat(cookie.getMaxAge()).isBetween(Duration.ofHours(8).minusSeconds(5), Duration.ofHours(8));
    }

    @Test
    void issue_sessionAlreadyPastItsMaximum_hasZeroMaxAge() {
        assertThat(cookies.issue("token", Instant.now().minusSeconds(1)).getMaxAge()).isEqualTo(Duration.ZERO);
    }

    @Test
    void clear_expiresTheCookieOnTheSamePath() {
        // Act
        var cookie = cookies.clear();

        // Assert
        assertThat(cookie.getValue()).isEmpty();
        assertThat(cookie.getMaxAge()).isEqualTo(Duration.ZERO);
        assertThat(cookie.getPath()).isEqualTo("/");
    }

    @Test
    void read_oneCookie_returnsItsValue() {
        var request = MockServerHttpRequest.post("/").cookie(new HttpCookie("__Host-wallet_refresh", "token")).build();

        assertThat(cookies.read(request)).isEqualTo("token");
    }

    @Test
    void read_noCookie_returnsNull() {
        assertThat(cookies.read(MockServerHttpRequest.post("/").build())).isNull();
    }

    @Test
    void read_twoCookies_failsWithInvalidSession() {
        var request = MockServerHttpRequest.post("/")
                .cookie(new HttpCookie("__Host-wallet_refresh", "a"), new HttpCookie("__Host-wallet_refresh", "b"))
                .build();

        assertThatThrownBy(() -> cookies.read(request)).isInstanceOf(InvalidSessionException.class);
    }
}
