package com.eudistack.ebw.infrastructure.controller.dto;

import com.eudistack.ebw.domain.model.AuthTokenPair;

public record AuthTokenResponse(
        String accessToken,
        String refreshToken,
        long expiresIn
) {
    public static AuthTokenResponse from(AuthTokenPair pair) {
        return new AuthTokenResponse(pair.accessToken(), pair.refreshToken(), pair.expiresIn());
    }
}
