package com.eudistack.ebw.wallet.config.application;

import com.eudistack.ebw.wallet.config.application.command.ApplyConfigurationCommand;
import com.eudistack.ebw.wallet.config.application.workflow.TenantWalletConfigurationWriter;
import com.eudistack.ebw.wallet.config.domain.model.ConfigurationAuditEvent;
import com.eudistack.ebw.wallet.config.domain.model.TenantWalletConfigDescriptor;
import com.eudistack.ebw.wallet.config.domain.model.WalletMode;
import com.eudistack.ebw.wallet.config.domain.port.ConfigurationAuditPort;
import com.eudistack.ebw.wallet.config.domain.port.DiscoveryCacheInvalidationPort;
import com.eudistack.ebw.wallet.config.domain.port.TenantConfigurationPort;
import com.eudistack.ebw.wallet.config.domain.service.TenantWalletConfigInvariants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link TenantWalletConfigurationWriter}.
 *
 * <p>Covers T-4 from tech-design §2.3. No Spring context — uses Mockito only.
 */
class TenantWalletConfigurationWriterTest {

    private TenantWalletConfigInvariants invariants;
    private TenantConfigurationPort tenantConfigurationPort;
    private ConfigurationAuditPort configurationAuditPort;
    private DiscoveryCacheInvalidationPort discoveryCacheInvalidationPort;

    private TenantWalletConfigurationWriter writer;

    @BeforeEach
    void setUp() {
        // Use a real invariants instance (pure domain, no mocking needed)
        invariants = new TenantWalletConfigInvariants();
        tenantConfigurationPort = mock(TenantConfigurationPort.class);
        configurationAuditPort = mock(ConfigurationAuditPort.class);
        discoveryCacheInvalidationPort = mock(DiscoveryCacheInvalidationPort.class);

        writer = new TenantWalletConfigurationWriter(
                invariants,
                tenantConfigurationPort,
                configurationAuditPort,
                discoveryCacheInvalidationPort);
    }

    // T-4: applyConfiguration for a BROWSER tenant emits an audit event with outcome=PERMIT.
    @Test
    void applyConfiguration_browserMode_emitsAuditEventWithPermitOutcome() {
        // Given
        String host = "acme.eudiw.example.com";
        String schemaName = "acme_business_wallet";
        String actor = "admin@example.com";

        ApplyConfigurationCommand command = new ApplyConfigurationCommand(
                schemaName,
                host,
                WalletMode.BROWSER,
                Optional.empty(),
                actor,
                "corr-001");

        TenantWalletConfigDescriptor savedDescriptor =
                TenantWalletConfigDescriptor.forBrowserTenant(schemaName, host);

        when(tenantConfigurationPort.save(any())).thenReturn(Mono.just(savedDescriptor));
        when(configurationAuditPort.append(any())).thenReturn(Mono.empty());
        when(discoveryCacheInvalidationPort.invalidate(host)).thenReturn(Mono.empty());

        // When
        Mono<TenantWalletConfigDescriptor> result = writer.applyConfiguration(command);

        // Then: the Mono completes and emits the saved descriptor
        StepVerifier.create(result)
                .assertNext(descriptor -> {
                    assertThat(descriptor.getHost()).isEqualTo(host);
                    assertThat(descriptor.getWalletMode()).isEqualTo(WalletMode.BROWSER);
                })
                .verifyComplete();

        // Verify that an audit event with outcome=PERMIT was appended
        ArgumentCaptor<ConfigurationAuditEvent> auditCaptor =
                ArgumentCaptor.forClass(ConfigurationAuditEvent.class);
        verify(configurationAuditPort).append(auditCaptor.capture());

        ConfigurationAuditEvent capturedEvent = auditCaptor.getValue();
        assertThat(capturedEvent.getOutcome()).isEqualTo(ConfigurationAuditEvent.Outcome.PERMIT);
        assertThat(capturedEvent.getActor()).isEqualTo(actor);
        assertThat(capturedEvent.getSchemaName()).isEqualTo(schemaName);

        // Verify cache invalidation was requested
        verify(discoveryCacheInvalidationPort).invalidate(host);
    }
}
