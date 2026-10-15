package com.eudistack.ebw.domain.model;

import java.time.Duration;

/** Lifetime and issuer of the access tokens issued by {@code AuthTokenService}. */
public record AuthTokenSettings(
        Duration accessTokenTtl,
        String issuer
) {
}
