package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.port.KeyManagerPort;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link KeyManagerResolver} per-tenant adapter resolution.
 *
 * <p>Spec: EUDISTACK-533 AC-01, AC-02, EC-01, ES-02.</p>
 */
class KeyManagerResolverTest {

    private KeyManagerPort dbAdapter;
    private KeyManagerPort passkeyPrfAdapter;
    private KeyManagerResolver resolver;

    @BeforeEach
    void setUp() {
        dbAdapter = mock(KeyManagerPort.class);
        passkeyPrfAdapter = mock(KeyManagerPort.class);
        resolver = new KeyManagerResolver(dbAdapter, passkeyPrfAdapter);
    }

    // --- AC-01: DB tenant resolves to the DB adapter ---

    @Test
    void resolve_givenKeyManagerDB_returnsDbAdapter() {
        KeyManagerPort result = resolver.resolve(KeyManager.DB);
        assertThat(result).isSameAs(dbAdapter);
    }

    // --- AC-02: PASSKEY_PRF tenant resolves to the passkey-prf adapter ---

    @Test
    void resolve_givenKeyManagerPASSKEY_PRF_returnsPasskeyPrfAdapter() {
        KeyManagerPort result = resolver.resolve(KeyManager.PASSKEY_PRF);
        assertThat(result).isSameAs(passkeyPrfAdapter);
    }

    // --- EC-01: null key manager (BROWSER mode) defaults to DB adapter ---

    @Test
    void resolve_givenNull_returnsDbAdapterAsDefault() {
        KeyManagerPort result = resolver.resolve(null);
        assertThat(result).isSameAs(dbAdapter);
    }

    // --- ES-02: resolver is stateless — repeated calls return the same instance ---

    @Test
    void resolve_repeatedCalls_returnSameInstanceWithoutCrossContamination() {
        KeyManagerPort first = resolver.resolve(KeyManager.DB);
        KeyManagerPort second = resolver.resolve(KeyManager.PASSKEY_PRF);
        KeyManagerPort third = resolver.resolve(KeyManager.DB);

        assertThat(first).isSameAs(third).isSameAs(dbAdapter);
        assertThat(second).isSameAs(passkeyPrfAdapter);
    }
}
