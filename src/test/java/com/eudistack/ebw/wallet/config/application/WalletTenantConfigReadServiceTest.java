package com.eudistack.ebw.wallet.config.application;

import com.eudistack.ebw.wallet.config.application.workflow.WalletTenantConfigReadService;
import com.eudistack.ebw.wallet.config.domain.model.TenantWalletConfigDescriptor;
import com.eudistack.ebw.wallet.config.domain.port.TenantConfigurationPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link WalletTenantConfigReadService}.
 *
 * <p>Covers T-1 from tech-design §2.3. No Spring context — uses Mockito only.
 */
class WalletTenantConfigReadServiceTest {

    private TenantConfigurationPort tenantConfigurationPort;
    private WalletTenantConfigReadService readService;

    @BeforeEach
    void setUp() {
        tenantConfigurationPort = mock(TenantConfigurationPort.class);
        readService = new WalletTenantConfigReadService(tenantConfigurationPort);
    }

    // T-1: retrieveDescriptor returns the descriptor emitted by TenantConfigurationPort for a browser tenant.
    @Test
    void retrieveDescriptor_browserTenantExists_returnsDescriptor() {
        // Given
        String host = "acme.eudiw.example.com";
        TenantWalletConfigDescriptor expected =
                TenantWalletConfigDescriptor.forBrowserTenant("acme_business_wallet", host);
        when(tenantConfigurationPort.findByHost(host)).thenReturn(Mono.just(expected));

        // When
        Mono<TenantWalletConfigDescriptor> result = readService.retrieveDescriptor(host);

        // Then
        StepVerifier.create(result)
                .assertNext(descriptor -> {
                    assertThat(descriptor.getHost()).isEqualTo(host);
                    assertThat(descriptor.getWalletMode().getValue()).isEqualTo("browser");
                    assertThat(descriptor.getKeyManager()).isEmpty();
                })
                .verifyComplete();

        verify(tenantConfigurationPort).findByHost(host);
    }

    // T-1 (empty path): when no config exists, retrieveDescriptor propagates the empty Mono.
    @Test
    void retrieveDescriptor_tenantNotFound_returnsEmpty() {
        // Given
        String host = "unknown.example.com";
        when(tenantConfigurationPort.findByHost(host)).thenReturn(Mono.empty());

        // When
        Mono<TenantWalletConfigDescriptor> result = readService.retrieveDescriptor(host);

        // Then
        StepVerifier.create(result)
                .verifyComplete();

        verify(tenantConfigurationPort).findByHost(host);
    }
}
