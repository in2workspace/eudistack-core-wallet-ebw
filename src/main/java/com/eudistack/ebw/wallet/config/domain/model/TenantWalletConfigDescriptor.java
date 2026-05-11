package com.eudistack.ebw.wallet.config.domain.model;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Aggregate root representing the wallet configuration of a single tenant.
 *
 * <p>Immutable. All mutation produces a new instance via factory/builder patterns.
 *
 * <p>Invariant (FR-20): {@code walletMode=BROWSER} requires {@code keyManager} to be empty.
 * This is enforced by {@code TenantWalletConfigInvariants} before any persistence call.
 *
 * <p>Invariant: {@code naturalPersonsOnly} is always derived —
 * it is {@code true} if and only if {@code keyManager = HYBRID}.
 */
public final class TenantWalletConfigDescriptor {

    private final String schemaName;
    private final String host;
    private final WalletMode walletMode;
    private final Optional<KeyManager> keyManager;
    private final boolean naturalPersonsOnly;
    private final List<String> supportedCredentials;
    private final long version;

    private TenantWalletConfigDescriptor(
            String schemaName,
            String host,
            WalletMode walletMode,
            Optional<KeyManager> keyManager,
            boolean naturalPersonsOnly,
            List<String> supportedCredentials,
            long version) {
        this.schemaName = schemaName;
        this.host = host;
        this.walletMode = walletMode;
        this.keyManager = keyManager;
        this.naturalPersonsOnly = naturalPersonsOnly;
        this.supportedCredentials = Collections.unmodifiableList(supportedCredentials);
        this.version = version;
    }

    /**
     * Creates a BROWSER-mode descriptor with {@code keyManager=empty} and
     * {@code naturalPersonsOnly=false} (HYBRID not applicable for browser mode).
     *
     * <p>This factory is a convenience for the most common US-01 use case. Callers that need
     * a fully-parameterized instance (e.g. SERVER mode) should use {@link #of}.
     */
    public static TenantWalletConfigDescriptor forBrowserTenant(
            String schemaName,
            String host) {
        return new TenantWalletConfigDescriptor(
                schemaName,
                host,
                WalletMode.BROWSER,
                Optional.empty(),
                false,
                Collections.emptyList(),
                0L);
    }

    /**
     * Full-parameter factory for all wallet modes. Callers are responsible for
     * ensuring invariants hold (use {@code TenantWalletConfigInvariants.validatePairing}
     * before calling this method in any write path).
     */
    public static TenantWalletConfigDescriptor of(
            String schemaName,
            String host,
            WalletMode walletMode,
            Optional<KeyManager> keyManager,
            boolean naturalPersonsOnly,
            List<String> supportedCredentials,
            long version) {
        return new TenantWalletConfigDescriptor(
                schemaName,
                host,
                walletMode,
                keyManager,
                naturalPersonsOnly,
                supportedCredentials,
                version);
    }

    /**
     * Returns a new descriptor with the same values but an incremented {@code version}.
     */
    public TenantWalletConfigDescriptor withIncrementedVersion() {
        return new TenantWalletConfigDescriptor(
                schemaName,
                host,
                walletMode,
                keyManager,
                naturalPersonsOnly,
                supportedCredentials,
                version + 1);
    }

    public String getSchemaName() {
        return schemaName;
    }

    public String getHost() {
        return host;
    }

    public WalletMode getWalletMode() {
        return walletMode;
    }

    public Optional<KeyManager> getKeyManager() {
        return keyManager;
    }

    public boolean isNaturalPersonsOnly() {
        return naturalPersonsOnly;
    }

    public List<String> getSupportedCredentials() {
        return supportedCredentials;
    }

    public long getVersion() {
        return version;
    }
}
