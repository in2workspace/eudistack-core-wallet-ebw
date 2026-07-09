package com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto;

public record BlockOnboardingRequest(
        String credentialId,
        String correlationId
) {}
