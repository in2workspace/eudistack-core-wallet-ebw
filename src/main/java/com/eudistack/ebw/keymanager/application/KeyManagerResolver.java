package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.port.KeyManagerPort;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;

/**
 * Resolves the correct {@link KeyManagerPort} implementation for a given {@link KeyManager} type.
 *
 * <p>Replaces the {@code KeyManagerSpiFactory} described in EUDISTACK-474 architecture.md §5.1.
 * Added as workaround per EUDISTACK-533 R-1 decision — EUDISTACK-5 did not deliver a factory SPI.</p>
 *
 * <p>{@code null} key-manager (BROWSER-mode tenant) defaults to the {@code db} adapter,
 * which rejects both handshake calls with {@link UnsupportedOperationException} — the correct
 * response because browser tenants never reach the passkey-prf endpoints.</p>
 *
 * <p>Spec: EUDISTACK-474 FR-01, AC-01, AC-02; EUDISTACK-533 technical-design.md §3.4.</p>
 */
public class KeyManagerResolver {

    private final KeyManagerPort dbAdapter;
    private final KeyManagerPort passkeyPrfAdapter;

    public KeyManagerResolver(KeyManagerPort dbAdapter, KeyManagerPort passkeyPrfAdapter) {
        this.dbAdapter = dbAdapter;
        this.passkeyPrfAdapter = passkeyPrfAdapter;
    }

    /**
     * Returns the adapter for {@code keyManager}.
     *
     * @param keyManager the tenant's configured key manager, or {@code null} for BROWSER mode
     * @return the matching {@link KeyManagerPort} implementation
     */
    public KeyManagerPort resolve(KeyManager keyManager) {
        if (keyManager == null) {
            return dbAdapter;
        }
        return switch (keyManager) {
            case DB -> dbAdapter;
            case PASSKEY_PRF -> passkeyPrfAdapter;
        };
    }
}
