package com.eudistack.ebw.keymanager.domain.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ConsumerOrigin} enum.
 *
 * <p>Covers EUDISTACK-407 FR-60.</p>
 */
class ConsumerOriginTest {

    @Test
    void allValues_arePresent() {
        assertThat(ConsumerOrigin.values()).containsExactlyInAnyOrder(
                ConsumerOrigin.STORAGE,
                ConsumerOrigin.OID4VCI_RESPONDER,
                ConsumerOrigin.OID4VP_RESPONDER,
                ConsumerOrigin.SYSTEM
        );
    }

    @Test
    void system_isDefaultValue() {
        // SYSTEM is used when X-Consumer-Origin header is absent
        assertThat(ConsumerOrigin.valueOf("SYSTEM")).isEqualTo(ConsumerOrigin.SYSTEM);
    }
}
