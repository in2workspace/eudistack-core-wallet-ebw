package com.eudistack.ebw.infrastructure.adapter.audit;

import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

class ConfiguredAuditAccessTokenProviderTest {

    @Test
    void accessToken_configuredToken_returnsIt() {
        // Arrange
        var provider = new ConfiguredAuditAccessTokenProvider("token-1");

        // Act & Assert
        StepVerifier.create(provider.accessToken(null)).expectNext("token-1").verifyComplete();
        StepVerifier.create(provider.refreshAccessToken(null)).expectNext("token-1").verifyComplete();
    }

    @Test
    void accessToken_blankToken_fails() {
        // Arrange
        var provider = new ConfiguredAuditAccessTokenProvider("");

        // Act & Assert
        StepVerifier.create(provider.accessToken(null)).expectError(IllegalStateException.class).verify();
    }
}
