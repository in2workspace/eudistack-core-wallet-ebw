package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.port.KeyManagerPort;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link KeyManagerResolver} per-tenant adapter resolution.
 *
 * <p>Spec: EUDISTACK-533 AC-01, AC-02, EC-01, EC-02, EC-03, ES-02.</p>
 */
class KeyManagerResolverTest {

    private KeyManagerPort dbAdapter;
    private KeyManagerPort hybridAdapter;
    private KeyManagerResolver resolver;

    @BeforeEach
    void setUp() {
        dbAdapter = mock(KeyManagerPort.class);
        hybridAdapter = mock(KeyManagerPort.class);
        resolver = new KeyManagerResolver(dbAdapter, hybridAdapter);
    }

    // --- AC-01: DB tenant resolves to the DB adapter ---

    @Test
    void resolve_givenKeyManagerDB_returnsDbAdapter() {
        KeyManagerPort result = resolver.resolve(KeyManager.DB);
        assertThat(result).isSameAs(dbAdapter);
    }

    // --- AC-02: HYBRID tenant resolves to the hybrid adapter ---

    @Test
    void resolve_givenKeyManagerHYBRID_returnsHybridAdapter() {
        KeyManagerPort result = resolver.resolve(KeyManager.HYBRID);
        assertThat(result).isSameAs(hybridAdapter);
    }

    // --- EC-01: null key manager (BROWSER mode) defaults to DB adapter ---

    @Test
    void resolve_givenNull_returnsDbAdapterAsDefault() {
        KeyManagerPort result = resolver.resolve(null);
        assertThat(result).isSameAs(dbAdapter);
    }

    // --- EC-02: HSM not yet implemented — fail fast ---

    @Test
    void resolve_givenKeyManagerHSM_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> resolver.resolve(KeyManager.HSM))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("hsm");
    }

    // --- EC-03: QTSP not yet implemented — fail fast ---

    @Test
    void resolve_givenKeyManagerQTSP_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> resolver.resolve(KeyManager.QTSP))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("qtsp");
    }

    // --- ES-02: resolver is stateless — repeated calls return the same instance ---

    @Test
    void resolve_repeatedCalls_returnSameInstanceWithoutCrossContamination() {
        KeyManagerPort first = resolver.resolve(KeyManager.DB);
        KeyManagerPort second = resolver.resolve(KeyManager.HYBRID);
        KeyManagerPort third = resolver.resolve(KeyManager.DB);

        assertThat(first).isSameAs(third).isSameAs(dbAdapter);
        assertThat(second).isSameAs(hybridAdapter);
    }
}
