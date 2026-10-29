package com.eudistack.ebw.infrastructure.adapter.properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RateLimitPropertiesTest {

    @ParameterizedTest
    @ValueSource(ints = {0, -1})
    void constructor_trustedProxiesBelowOne_isRejected(int proxies) {
        // Act + Assert
        assertThatThrownBy(() -> new RateLimitProperties(3, 10, 10, 20, 60, 20, 60, 30, proxies, Duration.ofHours(1)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("trusted-proxies");
    }

    @Test
    void constructor_oneTrustedProxy_isAccepted() {
        // Act
        var properties = new RateLimitProperties(3, 10, 10, 20, 60, 20, 60, 30, 1, Duration.ofHours(1));

        // Assert
        assertThat(properties.trustedProxies()).isEqualTo(1);
    }
}
