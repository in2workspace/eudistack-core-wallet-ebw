package com.eudistack.ebw.infrastructure.controller.dto;

import com.eudistack.ebw.domain.model.IssuedSession;

import java.util.UUID;

/** {@code Session} of the contract. The refresh token only travels in the cookie. */
public record SessionResponse(String accessToken, String tokenType, long expiresIn, UUID passkeyId) {

    public static SessionResponse from(IssuedSession session) {
        return new SessionResponse(session.accessToken(), "Bearer", session.expiresIn(), session.passkeyId());
    }
}
