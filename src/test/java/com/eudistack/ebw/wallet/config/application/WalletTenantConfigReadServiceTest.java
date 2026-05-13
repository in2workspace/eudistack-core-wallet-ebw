package com.eudistack.ebw.wallet.config.application;

import com.eudistack.ebw.wallet.config.application.workflow.WalletTenantConfigReadService;
import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
import com.eudistack.ebw.wallet.config.domain.model.TenantWalletConfigDescriptor;
import com.eudistack.ebw.wallet.config.domain.model.WalletMode;
import com.eudistack.ebw.wallet.config.domain.port.TenantConfigurationPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Collections;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link WalletTenantConfigReadService}.
 *
 * <p>Covers T-1 (AC-1a, AC-1c, AC-1d) and T-2 (AC-1e) from tech-design §2.3 (EUDISTACK-412),
 * plus T-1/T-2 for the {@code server}+{@code db-tde} case (EUDISTACK-413 AC-1a). No Spring
 * context — uses Mockito only. The discovery read path is mode-agnostic and read-only.
 */
class WalletTenantConfigReadServiceTest {

    private TenantConfigurationPort tenantConfigurationPort;
    private WalletTenantConfigReadService readService;

    @BeforeEach
    void setUp() {
        tenantConfigurationPort = mock(TenantConfigurationPort.class);
        readService = new WalletTenantConfigReadService(tenantConfigurationPort);
    }

    // ------------------------------------------------------------------
    // T-1 — happy path: the descriptor maps cleanly to the 4-field public projection
    // ------------------------------------------------------------------

    /**
     * T-1: {@code retrieveDescriptor(host)} returns the descriptor emitted by the port for a
     * browser tenant. The descriptor carries exactly the data the public 4-field projection needs
     * ({@code walletMode}, {@code naturalPersonsOnly}, {@code supportedCredentials=[]},
     * {@code version}) with the {@code keyManager} {@link Optional} empty — so the DTO built from it
     * cannot leak {@code key_manager} (AC-1c, AC-1d, AD-1bis). The DTO-level assertion (no
     * {@code key_manager} field in the JSON) lives in {@code WalletTenantConfigDiscoveryControllerIT}
     * to keep this application-layer test free of infrastructure imports.
     */
    @Test
    void retrieveDescriptor_browserTenantExists_returnsDescriptorWithFourFieldDataAndNoKeyManager() {
        // Given
        String host = "acme.eudiw.example.com";
        TenantWalletConfigDescriptor descriptor = TenantWalletConfigDescriptor.of(
                "acme_business_wallet", host, WalletMode.BROWSER,
                Optional.empty(), false, Collections.emptyList(), 7L);
        when(tenantConfigurationPort.findByHost(host)).thenReturn(Mono.just(descriptor));

        // When
        Mono<TenantWalletConfigDescriptor> result = readService.retrieveDescriptor(host);

        // Then — descriptor surfaces the browser tenant with no key_manager
        StepVerifier.create(result)
                .assertNext(d -> {
                    assertThat(d.getHost()).isEqualTo(host);
                    assertThat(d.getWalletMode()).isEqualTo(WalletMode.BROWSER);
                    assertThat(d.getKeyManager()).isEmpty();
                    assertThat(d.isNaturalPersonsOnly()).isFalse();
                    assertThat(d.getSupportedCredentials()).isEmpty();
                    assertThat(d.getVersion()).isEqualTo(7L);
                })
                .verifyComplete();

        verify(tenantConfigurationPort).findByHost(host);
        verifyNoMoreInteractions(tenantConfigurationPort);
    }

    /**
     * T-1 (empty path): when the port emits an empty {@link Mono}, the service propagates it
     * unchanged — the controller turns the empty signal into an HTTP 404 (AC-3a). No write side
     * is involved.
     */
    @Test
    void retrieveDescriptor_tenantNotFound_propagatesEmptyMono() {
        // Given
        String host = "unknown.example.com";
        when(tenantConfigurationPort.findByHost(host)).thenReturn(Mono.empty());

        // When
        Mono<TenantWalletConfigDescriptor> result = readService.retrieveDescriptor(host);

        // Then
        StepVerifier.create(result)
                .verifyComplete();

        verify(tenantConfigurationPort).findByHost(host);
        verifyNoMoreInteractions(tenantConfigurationPort);
    }

    // ------------------------------------------------------------------
    // T-2 — host normalisation (AC-1e)
    // ------------------------------------------------------------------

    /**
     * T-2: the service does no host transformation of its own — it forwards the host it is given
     * straight to {@link TenantConfigurationPort#findByHost} with no extra I/O. Lowercasing /
     * port-stripping of the {@code Host} header is the caller's responsibility: the controller
     * lowercases the header value, and the R2DBC adapter lowercases its input before the lookup
     * (see {@code WalletTenantConfigDiscoveryControllerIT#upperCaseHostIsNormalisedAndReturns200}
     * and {@code WalletTenantConfigR2dbcAdapter#findByHost}). Here we assert the service is a
     * thin pass-through: exactly one port call, with exactly the argument supplied.
     */
    @Test
    void retrieveDescriptor_forwardsHostToPortUnchanged_withSinglePortCallAndNoOtherIo() {
        // Given — an already-normalised lowercase host (the contract: caller normalises)
        String normalisedHost = "acme.eudiw.example.com";
        TenantWalletConfigDescriptor descriptor =
                TenantWalletConfigDescriptor.forBrowserTenant("acme_business_wallet", normalisedHost);
        when(tenantConfigurationPort.findByHost(normalisedHost)).thenReturn(Mono.just(descriptor));

        // When
        Mono<TenantWalletConfigDescriptor> result = readService.retrieveDescriptor(normalisedHost);

        // Then — single port interaction, argument forwarded verbatim
        StepVerifier.create(result)
                .expectNext(descriptor)
                .verifyComplete();

        verify(tenantConfigurationPort).findByHost(normalisedHost);
        verifyNoMoreInteractions(tenantConfigurationPort);
    }

    // ------------------------------------------------------------------
    // EUDISTACK-413 — T-1/T-2 server+db-tde: service is mode-agnostic (AC-1a)
    // ------------------------------------------------------------------

    /**
     * EUDISTACK-413 T-1 (server case): {@code retrieveDescriptor(host)} for a {@code server}+
     * {@code db-tde} tenant returns the descriptor with {@code walletMode=SERVER},
     * {@code keyManager=Optional.of(DB_TDE)}, {@code naturalPersonsOnly=false},
     * {@code supportedCredentials=[]}, and the correct {@code version}.
     *
     * <p>The service is a thin pass-through regardless of mode — the domain aggregate already
     * carries {@code keyManager} internally; the public DTO layer (DiscoveryResponseDto) is what
     * omits it from the HTTP response body (AD-1bis). Keeping this assertion at the service layer
     * verifies that the service does not accidentally strip or alter the {@code keyManager} field.
     */
    @Test
    void retrieveDescriptor_serverDbTdeTenantExists_returnsDescriptorWithKeyManagerPresent() {
        // Given
        String host = "dome.eudistack.example.com";
        TenantWalletConfigDescriptor descriptor = TenantWalletConfigDescriptor.of(
                "dome", host, WalletMode.SERVER,
                Optional.of(KeyManager.DB_TDE), false, Collections.emptyList(), 1L);
        when(tenantConfigurationPort.findByHost(host)).thenReturn(Mono.just(descriptor));

        // When
        Mono<TenantWalletConfigDescriptor> result = readService.retrieveDescriptor(host);

        // Then — descriptor surfaces server mode with db-tde key manager intact
        StepVerifier.create(result)
                .assertNext(d -> {
                    assertThat(d.getHost()).isEqualTo(host);
                    assertThat(d.getWalletMode()).isEqualTo(WalletMode.SERVER);
                    assertThat(d.getKeyManager()).contains(KeyManager.DB_TDE);
                    assertThat(d.isNaturalPersonsOnly()).isFalse();
                    assertThat(d.getSupportedCredentials()).isEmpty();
                    assertThat(d.getVersion()).isEqualTo(1L);
                })
                .verifyComplete();

        verify(tenantConfigurationPort).findByHost(host);
        verifyNoMoreInteractions(tenantConfigurationPort);
    }

    /**
     * EUDISTACK-413 T-2 (server, port-strip normalisation): the service forwards the host
     * argument to the port unchanged. An uppercase host with port ({@code DOME.EUDISTACK.EXAMPLE.COM:443})
     * has already been normalised by the controller before reaching the service — this test verifies
     * that the service itself does not perform any additional transformation.
     */
    @Test
    void retrieveDescriptor_serverTenant_forwardsNormalisedHostToPortUnchanged() {
        // Given — controller has already lowercased and stripped the port
        String normalisedHost = "dome.eudistack.example.com";
        TenantWalletConfigDescriptor descriptor = TenantWalletConfigDescriptor.of(
                "dome", normalisedHost, WalletMode.SERVER,
                Optional.of(KeyManager.DB_TDE), false, Collections.emptyList(), 2L);
        when(tenantConfigurationPort.findByHost(normalisedHost)).thenReturn(Mono.just(descriptor));

        // When
        Mono<TenantWalletConfigDescriptor> result = readService.retrieveDescriptor(normalisedHost);

        // Then — single port call, argument forwarded verbatim
        StepVerifier.create(result)
                .expectNext(descriptor)
                .verifyComplete();

        verify(tenantConfigurationPort).findByHost(normalisedHost);
        verifyNoMoreInteractions(tenantConfigurationPort);
    }
}
