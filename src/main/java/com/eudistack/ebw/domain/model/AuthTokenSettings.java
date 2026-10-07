package com.eudistack.ebw.domain.model;

import java.time.Duration;

/** Lifetimes and issuer of the wallet session tokens issued by {@code AuthTokenService}. */
public record AuthTokenSettings(
        Duration accessTokenTtl,
        Duration refreshTokenTtl,
        String issuer
) {
}
