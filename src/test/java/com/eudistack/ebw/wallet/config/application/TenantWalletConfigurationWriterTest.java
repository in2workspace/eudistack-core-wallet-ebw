package com.eudistack.ebw.wallet.config.application;

import com.eudistack.ebw.wallet.config.application.command.ApplyConfigurationCommand;
import com.eudistack.ebw.wallet.config.application.workflow.TenantWalletConfigurationWriter;
import com.eudistack.ebw.wallet.config.domain.exception.ConfigInvariantViolationException;
import com.eudistack.ebw.wallet.config.domain.model.ConfigurationAuditEvent;
import com.eudistack.ebw.wallet.config.domain.model.ConfigurationAuditEvent.Event;
import com.eudistack.ebw.wallet.config.domain.model.ConfigurationAuditEvent.FieldDelta;
import com.eudistack.ebw.wallet.config.domain.model.ConfigurationAuditEvent.Outcome;
import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
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

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link TenantWalletConfigurationWriter}.
 *
 * <p>Covers T-4 from tech-design §2.3 plus the audit {@code field_changes} from/to deltas and the
 * create-vs-update event derivation (B1 / AC-3a / AC-3b / FR-30). No Spring context — Mockito only.
 */
class TenantWalletConfigurationWriterTest {

    private static final String HOST = "acme.eudiw.example.com";
    private static final String SCHEMA_NAME = "acme";
    private static final String ACTOR = "admin@example.com";

    private TenantWalletConfigInvariants invariants;
    private TenantConfigurationPort tenantConfigurationPort;
    private ConfigurationAuditPort configurationAuditPort;
    private DiscoveryCacheInvalidationPort discoveryCacheInvalidationPort;

    private TenantWalletConfigurationWriter writer;

    @BeforeEach
    void setUp() {
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

    private ApplyConfigurationCommand browserCommand() {
        return new ApplyConfigurationCommand(
                SCHEMA_NAME, HOST, WalletMode.BROWSER, Optional.empty(), null, ACTOR, "corr-001");
    }

    private ConfigurationAuditEvent capturePermitEvent() {
        ArgumentCaptor<ConfigurationAuditEvent> captor =
                ArgumentCaptor.forClass(ConfigurationAuditEvent.class);
        verify(configurationAuditPort).append(captor.capture());
        return captor.getValue();
    }

    // ------------------------------------------------------------------
    // T-4 + B1: create (no before image) → CONFIG_CREATED + from/to deltas
    // ------------------------------------------------------------------

    @Test
    void applyConfiguration_browserCreate_emitsConfigCreatedWithFromToDeltas() {
        // Given: no before image
        when(tenantConfigurationPort.findBySchemaName(SCHEMA_NAME)).thenReturn(Mono.empty());
        TenantWalletConfigDescriptor saved =
                TenantWalletConfigDescriptor.forBrowserTenant(SCHEMA_NAME, HOST);
        when(tenantConfigurationPort.save(any(), any())).thenReturn(Mono.just(saved));
        when(configurationAuditPort.append(any())).thenReturn(Mono.empty());
        when(discoveryCacheInvalidationPort.invalidate(HOST)).thenReturn(Mono.empty());

        // When
        StepVerifier.create(writer.applyConfiguration(browserCommand()))
                .assertNext(d -> {
                    assertThat(d.getHost()).isEqualTo(HOST);
                    assertThat(d.getWalletMode()).isEqualTo(WalletMode.BROWSER);
                })
                .verifyComplete();

        // Then: the audit event is CONFIG_CREATED / PERMIT and the writer produced the deltas
        ConfigurationAuditEvent event = capturePermitEvent();
        assertThat(event.getEvent()).isEqualTo(Event.CONFIG_CREATED);
        assertThat(event.getOutcome()).isEqualTo(Outcome.PERMIT);
        assertThat(event.getActor()).isEqualTo(ACTOR);
        assertThat(event.getSchemaName()).isEqualTo(SCHEMA_NAME);

        Map<String, FieldDelta> changes = event.getFieldChanges();
        assertThat(changes).containsEntry("wallet_mode", new FieldDelta(null, "browser"));
        assertThat(changes).containsEntry("key_manager", new FieldDelta(null, null));

        verify(discoveryCacheInvalidationPort).invalidate(HOST);
    }

    // ------------------------------------------------------------------
    // B1: update (before image present) → CONFIG_UPDATED + only changed fields
    // ------------------------------------------------------------------

    @Test
    void applyConfiguration_browserUpdate_emitsConfigUpdatedWithOnlyChangedFields() {
        // Given: an existing browser tenant; the update flips natural_persons_only? No — for a
        // browser tenant npo is always derived as false, so simulate an existing row that had
        // npo=true (e.g. a stale value) and confirm only natural_persons_only is reported.
        TenantWalletConfigDescriptor before = TenantWalletConfigDescriptor.of(
                SCHEMA_NAME, HOST, WalletMode.BROWSER, Optional.empty(), true,
                Collections.emptyList(), 1L);
        TenantWalletConfigDescriptor saved = TenantWalletConfigDescriptor.of(
                SCHEMA_NAME, HOST, WalletMode.BROWSER, Optional.empty(), false,
                Collections.emptyList(), 2L);
        when(tenantConfigurationPort.findBySchemaName(SCHEMA_NAME)).thenReturn(Mono.just(before));
        when(tenantConfigurationPort.save(any(), any())).thenReturn(Mono.just(saved));
        when(configurationAuditPort.append(any())).thenReturn(Mono.empty());
        when(discoveryCacheInvalidationPort.invalidate(HOST)).thenReturn(Mono.empty());

        // When
        StepVerifier.create(writer.applyConfiguration(browserCommand()))
                .expectNextCount(1)
                .verifyComplete();

        // Then
        ConfigurationAuditEvent event = capturePermitEvent();
        assertThat(event.getEvent()).isEqualTo(Event.CONFIG_UPDATED);
        assertThat(event.getOutcome()).isEqualTo(Outcome.PERMIT);
        assertThat(event.getFieldChanges())
                .containsExactly(Map.entry("natural_persons_only", new FieldDelta("true", "false")));
    }

    // ------------------------------------------------------------------
    // AC-2d: invariant violation → CONFIG_REJECTED audit, no save/invalidate
    // ------------------------------------------------------------------

    @Test
    void applyConfiguration_browserWithKeyManager_emitsRejectionAndNeverPersists() {
        when(configurationAuditPort.append(any())).thenReturn(Mono.empty());
        ApplyConfigurationCommand command = new ApplyConfigurationCommand(
                SCHEMA_NAME, HOST, WalletMode.BROWSER, Optional.of(KeyManager.HYBRID),
                null, ACTOR, "corr-deny");

        StepVerifier.create(writer.applyConfiguration(command))
                .expectError(ConfigInvariantViolationException.class)
                .verify();

        ConfigurationAuditEvent event = capturePermitEvent();
        assertThat(event.getEvent()).isEqualTo(Event.CONFIG_REJECTED);
        assertThat(event.getOutcome()).isEqualTo(Outcome.DENY);
        assertThat(event.getFieldChanges())
                .containsEntry("key_manager", new FieldDelta(null, "hybrid"));

        verify(tenantConfigurationPort, never()).save(any(), any());
        verify(discoveryCacheInvalidationPort, never()).invalidate(any());
    }
}
