package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.port.KeyManagerPort;
import com.eudistack.ebw.keymanager.infrastructure.adapter.service.DbKeyManagerService;
import com.eudistack.ebw.keymanager.infrastructure.adapter.service.HybridKeyManagerAdapter;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Coexistence test: verifies that a {@code db} tenant and a {@code hybrid} tenant
 * in the same deployment resolve to independent adapter instances with no shared state.
 *
 * <p>Uses concrete instances (no Spring context required — {@link KeyManagerResolver}
 * is a pure-Java stateless class with no framework dependencies). Testcontainers is
 * deliberately omitted per task note: the factory is stateless.</p>
 *
 * <p>Spec: EUDISTACK-533 AC-02, EC-03.</p>
 */
@Tag("integration")
class KeyManagerCoexistenceIT {

    @Test
    void dbTenantAndHybridTenant_resolveToDistinctAdapters_withNoSharedState() {
        DbKeyManagerService dbAdapter = mock(DbKeyManagerService.class);
        HybridKeyManagerAdapter hybridAdapter = mock(HybridKeyManagerAdapter.class);
        KeyManagerResolver resolver = new KeyManagerResolver(dbAdapter, hybridAdapter);

        KeyManagerPort dbTenantAdapter = resolver.resolve(KeyManager.DB);
        KeyManagerPort hybridTenantAdapter = resolver.resolve(KeyManager.HYBRID);

        assertThat(dbTenantAdapter).isSameAs(dbAdapter);
        assertThat(hybridTenantAdapter).isSameAs(hybridAdapter);
        assertThat(dbTenantAdapter).isNotSameAs(hybridTenantAdapter);
    }

    @Test
    void resolverIsDeterministic_repeatedResolutionReturnsSameInstance() {
        DbKeyManagerService dbAdapter = mock(DbKeyManagerService.class);
        HybridKeyManagerAdapter hybridAdapter = mock(HybridKeyManagerAdapter.class);
        KeyManagerResolver resolver = new KeyManagerResolver(dbAdapter, hybridAdapter);

        KeyManagerPort first = resolver.resolve(KeyManager.DB);
        resolver.resolve(KeyManager.HYBRID);
        KeyManagerPort second = resolver.resolve(KeyManager.DB);

        assertThat(first).isSameAs(second);
    }

    @Test
    void hybridAdapterResolution_doesNotAffectDbAdapterBehaviour() {
        DbKeyManagerService dbAdapter = mock(DbKeyManagerService.class);
        HybridKeyManagerAdapter hybridAdapter = mock(HybridKeyManagerAdapter.class);
        KeyManagerResolver resolver = new KeyManagerResolver(dbAdapter, hybridAdapter);

        resolver.resolve(KeyManager.HYBRID);
        KeyManagerPort stillDb = resolver.resolve(KeyManager.DB);

        assertThat(stillDb).isSameAs(dbAdapter)
                .isInstanceOf(DbKeyManagerService.class);
    }
}
