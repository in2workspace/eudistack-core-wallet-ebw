package com.eudistack.ebw.wallet.config.application.workflow;

import com.eudistack.ebw.wallet.config.application.command.ApplyConfigurationCommand;
import com.eudistack.ebw.wallet.config.domain.exception.ConfigInvariantViolationException;
import com.eudistack.ebw.wallet.config.domain.model.ConfigurationAuditEvent;
import com.eudistack.ebw.wallet.config.domain.model.ConfigurationAuditEvent.Event;
import com.eudistack.ebw.wallet.config.domain.model.ConfigurationAuditEvent.FieldDelta;
import com.eudistack.ebw.wallet.config.domain.model.ConfigurationAuditEvent.Outcome;
import com.eudistack.ebw.wallet.config.domain.model.ConfigurationAuditEvent.Plane;
import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Application use case — sole write entry point for tenant wallet configuration.
 *
 * <p>Orchestrates the following sequence (all steps are mandatory):
 * <ol>
 *   <li>Validate the {@code walletMode}/{@code keyManager} pairing via
 *       {@link TenantWalletConfigInvariants#validatePairing} (synchronous, FR-20/FR-21).</li>
 *   <li>Fetch the existing row (the "before image") so the create-vs-update distinction and the
 *       audit {@code field_changes} from/to deltas can be computed (AC-3a / AC-3b / FR-30).</li>
 *   <li>Persist the descriptor via {@link TenantConfigurationPort#save}.</li>
 *   <li>Append a PERMIT audit entry ({@code CONFIG_CREATED} when there was no before image,
 *       {@code CONFIG_UPDATED} otherwise) via {@link ConfigurationAuditPort#append}.</li>
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
            // On the rejection path the before/after diff is not meaningful — record only the
            // attempted value as the "to" side; schemaName is validated by the audit adapter.
            Map<String, FieldDelta> rejected = Map.of(
                    ex.getConflictingField(), new FieldDelta(null, ex.getReceivedValue()));
            ConfigurationAuditEvent rejectionEvent = ConfigurationAuditEvent.create(
                    command.schemaName(),
                    command.actor(),
                    Event.CONFIG_REJECTED,
                    Plane.DISCOVERY,
                    rejected,
                    Outcome.DENY,
                    ex.getMessage(),
                    command.correlationId());
            return configurationAuditPort.append(rejectionEvent)
                    .then(Mono.error(ex));
        }

        boolean naturalPersonsOnly = invariants.deriveNaturalPersonsOnly(command.keyManager());

        return tenantConfigurationPort.findBySchemaName(command.schemaName())
                .map(Optional::of)
                .defaultIfEmpty(Optional.empty())
                .flatMap(beforeImage -> {
                    TenantWalletConfigDescriptor descriptor = TenantWalletConfigDescriptor.of(
                            command.schemaName(),
                            command.host(),
                            command.walletMode(),
                            command.keyManager(),
                            naturalPersonsOnly,
                            Collections.emptyList(),
                            0L);

                    return tenantConfigurationPort.save(descriptor, command.expectedVersion())
                            .flatMap(saved -> {
                                Event eventType = beforeImage.isPresent()
                                        ? Event.CONFIG_UPDATED : Event.CONFIG_CREATED;
                                Map<String, FieldDelta> fieldChanges =
                                        computeFieldChanges(beforeImage.orElse(null), saved);
                                ConfigurationAuditEvent permitEvent = ConfigurationAuditEvent.create(
                                        command.schemaName(),
                                        command.actor(),
                                        eventType,
                                        Plane.DISCOVERY,
                                        fieldChanges,
                                        Outcome.PERMIT,
                                        null,
                                        command.correlationId());
                                return configurationAuditPort.append(permitEvent).thenReturn(saved);
                            })
                            .flatMap(saved -> discoveryCacheInvalidationPort.invalidate(command.host())
                                    .onErrorResume(cacheError -> {
                                        log.error("Cache invalidation failed for host={}, error={}",
                                                command.host(), cacheError.getMessage());
                                        ConfigurationAuditEvent cacheFailureEvent =
                                                ConfigurationAuditEvent.create(
                                                        command.schemaName(),
                                                        command.actor(),
                                                        Event.CACHE_INVALIDATION_FAILED,
                                                        Plane.DISCOVERY,
                                                        Collections.emptyMap(),
                                                        Outcome.DENY,
                                                        cacheError.getMessage(),
                                                        command.correlationId());
                                        return configurationAuditPort.append(cacheFailureEvent);
                                    })
                                    .thenReturn(saved));
                })
                .doOnSuccess(saved -> log.info(
                        "Wallet tenant config applied: host={}, walletMode={}, version={}",
                        saved.getHost(), saved.getWalletMode(), saved.getVersion()))
                .doOnError(e -> log.error(
                        "Failed to apply wallet tenant config: host={}, error={}",
                        command.host(), e.getMessage()));
    }

    /**
     * Computes the {@code field_changes} map between the before image (may be {@code null} for a
     * create) and the persisted descriptor.
     *
     * <p>On a create (no before image) every discovery-plane field is recorded with
     * {@code from = null} — so AC-3a's {@code {"wallet_mode":{"from":null,"to":"browser"},
     * "key_manager":{"from":null,"to":null}}} is produced verbatim. On an update only the fields
     * that actually changed are included (AC-3b).
     *
     * <p>{@code wallet_mode} uses the enum's serialized value; {@code key_manager} uses ONLY the
     * enum type name (never a raw value — in US-01 it is always {@code null} for browser); the
     * {@code natural_persons_only} flag is recorded as {@code "true"}/{@code "false"}.
     */
    private static Map<String, FieldDelta> computeFieldChanges(
            TenantWalletConfigDescriptor before, TenantWalletConfigDescriptor after) {
        Map<String, FieldDelta> changes = new LinkedHashMap<>();
        boolean isCreate = before == null;

        String walletModeBefore = isCreate ? null : before.getWalletMode().getValue();
        String walletModeAfter = after.getWalletMode().getValue();
        if (isCreate || !Objects.equals(walletModeBefore, walletModeAfter)) {
            changes.put("wallet_mode", new FieldDelta(walletModeBefore, walletModeAfter));
        }

        String keyManagerBefore = isCreate ? null : keyManagerName(before.getKeyManager());
        String keyManagerAfter = keyManagerName(after.getKeyManager());
        if (isCreate || !Objects.equals(keyManagerBefore, keyManagerAfter)) {
            changes.put("key_manager", new FieldDelta(keyManagerBefore, keyManagerAfter));
        }

        String npoBefore = isCreate ? null : Boolean.toString(before.isNaturalPersonsOnly());
        String npoAfter = Boolean.toString(after.isNaturalPersonsOnly());
        if (!Objects.equals(npoBefore, npoAfter)) {
            changes.put("natural_persons_only", new FieldDelta(npoBefore, npoAfter));
        }

        return changes;
    }

    /** Returns the {@link KeyManager} enum type name, or {@code null} when absent. */
    private static String keyManagerName(Optional<KeyManager> keyManager) {
        return keyManager.map(Enum::name).orElse(null);
    }
}
