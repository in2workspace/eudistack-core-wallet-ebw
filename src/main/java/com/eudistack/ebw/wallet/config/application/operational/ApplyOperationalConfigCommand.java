package com.eudistack.ebw.wallet.config.application.operational;

import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
import com.eudistack.ebw.wallet.config.domain.model.operational.OperationalConfig;

import java.util.Objects;
import java.util.Optional;

/**
 * Immutable command driving the single write path of the operational configuration plane.
 *
 * <p>Carries all input required by {@link OperationalConfigWriter#apply} to execute
 * the validate → probe → persist → audit flow.
 *
 * <h2>POST vs PUT semantics via {@code ifMatchVersion}</h2>
 * <ul>
 *   <li>{@link Optional#empty()} — create (POST). The writer expects no pre-existing active
 *       configuration for this {@code keyManager}; a duplicate triggers a {@code 409} via
 *       the UNIQUE constraint on {@code key_manager}.</li>
 *   <li>{@link Optional#of(Long) Optional.of(N)} — update (PUT with {@code If-Match: "N"}).
 *       The writer loads the current descriptor, verifies the stored {@code version == N},
 *       then persists with {@code version = N + 1}. A mismatch causes
 *       {@code OptimisticLockingFailureException} → HTTP {@code 412}.</li>
 * </ul>
 *
 * <p>This is a pure domain-application record: zero Spring or infrastructure imports.
 */
public record ApplyOperationalConfigCommand(
        KeyManager keyManager,
        OperationalConfig operationalConfig,
        String actor,
        String correlationId,
        Optional<Long> ifMatchVersion
) {

    /**
     * Compact constructor — validates presence and non-blankness of all required fields.
     *
     * @throws NullPointerException     if any field is null
     * @throws IllegalArgumentException if {@code actor} or {@code correlationId} is blank
     */
    public ApplyOperationalConfigCommand {
        Objects.requireNonNull(keyManager, "keyManager must not be null");
        Objects.requireNonNull(operationalConfig, "operationalConfig must not be null");
        Objects.requireNonNull(actor, "actor must not be null");
        Objects.requireNonNull(correlationId, "correlationId must not be null");
        Objects.requireNonNull(ifMatchVersion, "ifMatchVersion must not be null");
        if (actor.isBlank()) {
            throw new IllegalArgumentException("actor must not be blank");
        }
        if (correlationId.isBlank()) {
            throw new IllegalArgumentException("correlationId must not be blank");
        }
    }
}
