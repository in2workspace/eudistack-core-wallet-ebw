package com.eudistack.ebw.domain.model;

import java.time.Duration;

/**
 * Groups the access/refresh-token TTLs and issuer under one value object so
 * {@code AuthTokenService}'s constructor stays within the project's parameter-count limit —
 * a plain domain record, not the Spring-bound {@code JwtProperties} it is built from, so the
 * domain layer stays free of an infrastructure-configuration dependency.
 */
public record TokenIssuanceSettings(
        Duration accessTokenTtl,
        Duration refreshTokenTtl,
        String issuer
) {
}
