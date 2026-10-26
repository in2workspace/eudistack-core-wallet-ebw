package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.model.RelyingPartySettings;
import com.eudistack.ebw.domain.model.exception.TenantConfigMissingException;
import com.eudistack.ebw.domain.service.WalletAuthSettingsService;
import com.eudistack.ebw.infrastructure.configuration.ActiveTenantDirectory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/** Unit tests for {@link TenantOrigins}. */
@ExtendWith(MockitoExtension.class)
class TenantOriginsTest {

    @Mock private ActiveTenantDirectory tenantDirectory;
    @Mock private WalletAuthSettingsService settingsService;

    private TenantOrigins tenantOrigins;

    @BeforeEach
    void setUp() {
        tenantOrigins = new TenantOrigins(tenantDirectory, settingsService);
    }

    @Test
    void refresh_activeTenants_loadsTheOriginsOfEachTenant() {
        // Arrange
        when(tenantDirectory.activeTenants()).thenReturn(Flux.just("sandbox", "kpmg"));
        when(settingsService.relyingParty()).thenReturn(Mono.deferContextual(ctx -> {
            String tenant = ctx.get(ReactorContextKeys.TENANT_DOMAIN);
            if ("kpmg".equals(tenant)) {
                return Mono.error(new TenantConfigMissingException(tenant, "ebw.webauthn.rp_id"));
            }
            return Mono.just(new RelyingPartySettings(tenant + ".stg.eudistack.net", "Wallet",
                    List.of("https://" + tenant + ".stg.eudistack.net")));
        }));

        // Act
        StepVerifier.create(tenantOrigins.refresh()).expectNext(1).verifyComplete();

        // Assert
        assertThat(tenantOrigins.originsOf("sandbox")).containsExactly("https://sandbox.stg.eudistack.net");
        assertThat(tenantOrigins.originsOf("kpmg")).isEmpty();
    }

    @Test
    void refresh_tenantRegistryUnavailable_keepsWhatItHad() {
        // Arrange
        when(tenantDirectory.activeTenants()).thenReturn(Flux.error(new IllegalStateException("db down")));

        // Act + Assert
        StepVerifier.create(tenantOrigins.refresh()).expectNext(0).verifyComplete();
        assertThat(tenantOrigins.originsOf("sandbox")).isEmpty();
    }

    @Test
    void refresh_tenantNoLongerActive_dropsItsOrigins() {
        // Arrange
        when(tenantDirectory.activeTenants()).thenReturn(Flux.just("sandbox", "kpmg"), Flux.just("sandbox"));
        when(settingsService.relyingParty()).thenReturn(Mono.deferContextual(ctx -> {
            String tenant = ctx.get(ReactorContextKeys.TENANT_DOMAIN);
            return Mono.just(new RelyingPartySettings(tenant + ".stg.eudistack.net", "Wallet",
                    List.of("https://" + tenant + ".stg.eudistack.net")));
        }));
        StepVerifier.create(tenantOrigins.refresh()).expectNext(2).verifyComplete();

        // Act
        StepVerifier.create(tenantOrigins.refresh()).expectNext(1).verifyComplete();

        // Assert
        assertThat(tenantOrigins.originsOf("kpmg")).isEmpty();
        assertThat(tenantOrigins.originsOf("sandbox")).containsExactly("https://sandbox.stg.eudistack.net");
    }

    @Test
    void refresh_activeTenantUnreadable_keepsItsPreviousOrigins() {
        // Arrange
        var failing = new AtomicBoolean();
        when(tenantDirectory.activeTenants()).thenReturn(Flux.just("sandbox"));
        when(settingsService.relyingParty()).thenReturn(Mono.defer(() -> failing.get()
                ? Mono.error(new TenantConfigMissingException("sandbox", "ebw.webauthn.rp_id"))
                : Mono.just(new RelyingPartySettings("sandbox.stg.eudistack.net", "Wallet",
                        List.of("https://sandbox.stg.eudistack.net")))));
        StepVerifier.create(tenantOrigins.refresh()).expectNext(1).verifyComplete();
        failing.set(true);

        // Act
        StepVerifier.create(tenantOrigins.refresh()).expectNext(0).verifyComplete();

        // Assert
        assertThat(tenantOrigins.originsOf("sandbox")).containsExactly("https://sandbox.stg.eudistack.net");
    }
}
