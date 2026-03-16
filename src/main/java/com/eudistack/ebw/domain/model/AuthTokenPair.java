package com.eudistack.ebw.domain.model;

public record AuthTokenPair(
        String accessToken,
        String refreshToken,
        long expiresIn
) {
}
