package com.eudistack.ebw.wallet.config.application.workflow;

import com.eudistack.ebw.wallet.config.application.command.ApplyConfigurationCommand;
import com.eudistack.ebw.wallet.config.domain.exception.ConfigInvariantViolationException;
import com.eudistack.ebw.wallet.config.domain.model.ConfigurationAuditEvent;
import com.eudistack.ebw.wallet.config.domain.model.ConfigurationAuditEvent.Event;
import com.eudistack.ebw.wallet.config.domain.model.ConfigurationAuditEvent.Outcome;
import com.eudistack.ebw.wallet.config.domain.model.ConfigurationAuditEvent.Plane;
import com.eudistack.ebw.wallet.config.domain.model.TenantWalletConfigDescriptor;
import com.eudistack.ebw.wallet.config.domain.port.ConfigurationAuditPort;
import com.eudistack.ebw.wallet.config.domain.port.DiscoveryCacheInvalidationPort;
import com.eudistack.ebw.wallet.config.domain.port.TenantConfigurationPort;
import com.eudistack.ebw.wallet.config.domain.service.TenantWalletConfigInvariants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Collections;

/**
 * Application use case — sole write entry point for tenant wallet configuration.
 *
 * <p>Orchestrates the following sequence (all steps are mandatory):
 * <ol>
 *   <li>Validate the {@code walletMode}/{@code keyManager} pairing via
 *       {@link TenantWalletConfigInvariants#validatePairing} (synchronous, FR-20/FR-21).</li>
 *   <li>Persist the descriptor via {@link TenantConfigurationPort#save}.</li>
 *   <li>Append a PERMIT audit entry via {@link ConfigurationAuditPort#append}.</li>
 *   <li>Fire-and-forget cache invalidation via {@link DiscoveryCacheInvalidationPort#invalidate}.
 *       Failures are recorded as {@code CACHE_INVALIDATION_FAILED} audit entries and do not
 *       propagate to the caller (AD-S3).</li>
 * </ol>
 *
 * <p>If step 1 throws, a {@code CONFIG_REJECTED / DENY} audit entry is appended before
 * re-throwing the original exception, so that every configuration attempt is traceable.
 */
@Service
public class TenantWalletConfigurationWriter {

    private static final Logger log = LoggerFactory.getLogger(TenantWalletConfigurationWriter.class);

    private final TenantWalletConfigInvariants invariants;
    private final TenantConfigurationPort tenantConfigurationPort;
    private final ConfigurationAuditPort configurationAuditPort;
    private final DiscoveryCacheInvalidationPort discoveryCacheInvalidationPort;

    public TenantWalletConfigurationWriter(
            TenantWalletConfigInvariants invariants,
            TenantConfigurationPort tenantConfigurationPort,
            ConfigurationAuditPort configurationAuditPort,
            DiscoveryCacheInvalidationPort discoveryCacheInvalidationPort) {
        this.invariants = invariants;
        this.tenantConfigurationPort = tenantConfigurationPort;
        this.configurationAuditPort = configurationAuditPort;
        this.discoveryCacheInvalidationPort = discoveryCacheInvalidationPort;
    }

    /**
     * Applies a new or updated wallet configuration for the tenant identified by the command.
     *
     * @param command the configuration command; must not be {@code null}
     * @return a {@link Mono} emitting the persisted descriptor (with updated {@code version})
     * @throws ConfigInvariantViolationException if the {@code walletMode}/{@code keyManager}
     *                                           pairing violates FR-20 or FR-21
     */
    public Mono<TenantWalletConfigDescriptor> applyConfiguration(ApplyConfigurationCommand command) {
        try {
            invariants.validatePairing(command.walletMode(), command.keyManager());
        } catch (ConfigInvariantViolationException ex) {
            log.warn("Configuration rejected for host={}, field={}, value={}",
                    command.host(), ex.getConflictingField(), ex.getReceivedValue());
            ConfigurationAuditEvent rejectionEvent = ConfigurationAuditEvent.create(
                    command.actor(),
                    Event.CONFIG_REJECTED,
                    Plane.DISCOVERY,
                    Collections.emptyMap(),
                    Outcome.DENY,
                    ex.getMessage(),
                    command.correlationId());
            return configurationAuditPort.append(rejectionEvent)
                    .then(Mono.error(ex));
        }

        boolean naturalPersonsOnly = invariants.deriveNaturalPersonsOnly(command.keyManager());
        TenantWalletConfigDescriptor descriptor = TenantWalletConfigDescriptor.of(
                command.schemaName(),
                command.host(),
                command.walletMode(),
                command.keyManager(),
                naturalPersonsOnly,
                Collections.emptyList(),
                0L);

        return tenantConfigurationPort.save(descriptor)
                .flatMap(saved -> {
                    Event eventType = saved.getVersion() <= 1 ? Event.CONFIG_CREATED : Event.CONFIG_UPDATED;
                    ConfigurationAuditEvent permitEvent = ConfigurationAuditEvent.create(
                            command.actor(),
                            eventType,
                            Plane.DISCOVERY,
                            Collections.emptyMap(),
                            Outcome.PERMIT,
                            null,
                            command.correlationId());
                    return configurationAuditPort.append(permitEvent).thenReturn(saved);
                })
                .flatMap(saved -> discoveryCacheInvalidationPort.invalidate(command.host())
                        .onErrorResume(cacheError -> {
                            log.error("Cache invalidation failed for host={}, error={}",
                                    command.host(), cacheError.getMessage());
                            ConfigurationAuditEvent cacheFailureEvent = ConfigurationAuditEvent.create(
                                    command.actor(),
                                    Event.CACHE_INVALIDATION_FAILED,
                                    Plane.DISCOVERY,
                                    Collections.emptyMap(),
                                    Outcome.PERMIT,
                                    cacheError.getMessage(),
                                    command.correlationId());
                            return configurationAuditPort.append(cacheFailureEvent);
                        })
                        .thenReturn(saved))
                .doOnSuccess(saved -> log.info(
                        "Wallet tenant config applied: host={}, walletMode={}, version={}",
                        saved.getHost(), saved.getWalletMode(), saved.getVersion()))
                .doOnError(e -> log.error(
                        "Failed to apply wallet tenant config: host={}, error={}",
                        command.host(), e.getMessage()));
    }
}
