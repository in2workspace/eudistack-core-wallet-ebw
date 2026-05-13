package com.eudistack.ebw.wallet.config.domain.model.operational;

import com.eudistack.ebw.wallet.config.domain.model.KeyManager;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Aggregate read-model for the operational configuration of a single tenant.
 *
 * <p>Combines the root row ({@code wallet_operational_config}) with the sealed subtype
 * ({@link OperationalConfig}) that holds the key-manager-specific parameters (e.g.
 * {@link DbTdeOperationalConfig} for {@code db-tde}).
 *
 * <p>Immutable. Built by {@code OperationalConfigR2dbcAdapter} from a join of the root row
 * and the appropriate sub-table row. Consumed by {@code OperationalConfigWriter} and by
 * downstream readers (US-08 health check, column-encryption consumers).
 *
 * <p>Invariants (enforced in compact constructor):
 * <ul>
 *   <li>All fields except {@code connectivityVerifiedAt} are non-null.</li>
 *   <li>{@code version} must be non-negative.</li>
 *   <li>The {@code activationStatus} and {@code connectivityVerifiedAt} pairing is consistent
 *       with the DB cross-field CHECK (AD-6): {@code ACTIVE} requires a non-empty timestamp;
 *       {@code PENDING_SPI} requires an empty timestamp.</li>
 * </ul>
 */
public record OperationalConfigDescriptor(
        UUID id,
        KeyManager keyManager,
        OperationalConfig operationalConfig,
        boolean isActive,
        ActivationStatus activationStatus,
        Optional<Instant> connectivityVerifiedAt,
        long version,
        String updatedBy,
        Instant updatedAt
) {

    /**
     * Compact constructor — validates invariants before the record is constructed.
     *
     * @throws IllegalArgumentException if any invariant is violated
     */
    public OperationalConfigDescriptor {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(keyManager, "keyManager must not be null");
        Objects.requireNonNull(operationalConfig, "operationalConfig must not be null");
        Objects.requireNonNull(activationStatus, "activationStatus must not be null");
        Objects.requireNonNull(connectivityVerifiedAt, "connectivityVerifiedAt must not be null");
        Objects.requireNonNull(updatedBy, "updatedBy must not be null");
        Objects.requireNonNull(updatedAt, "updatedAt must not be null");
        if (version < 0) {
            throw new IllegalArgumentException("version must be non-negative, got: " + version);
        }
        // Cross-field invariant mirroring the DB CHECK constraint (AD-6).
        if (activationStatus == ActivationStatus.ACTIVE && connectivityVerifiedAt.isEmpty()) {
            throw new IllegalArgumentException(
                    "activationStatus=ACTIVE requires a non-empty connectivityVerifiedAt");
        }
        if (activationStatus == ActivationStatus.PENDING_SPI
                && connectivityVerifiedAt.isPresent()) {
            throw new IllegalArgumentException(
                    "activationStatus=PENDING_SPI requires connectivityVerifiedAt to be empty");
        }
    }
}
