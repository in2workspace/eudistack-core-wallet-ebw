package com.eudistack.ebw.wallet.config.domain.model.operational;

/**
 * Lifecycle status of the operational configuration for a tenant.
 *
 * <p>The status tracks whether the key-manager connectivity has been verified and the
 * operational plane is ready for use:
 * <ul>
 *   <li>{@link #ACTIVE} — the probe for the tenant's {@code key_manager} has passed; the
 *       operational configuration is fully applied and ready for column-encryption consumers.</li>
 *   <li>{@link #PENDING_SPI} — the operational configuration has been persisted but the
 *       key-manager connectivity probe has not yet been registered (or has not passed). This is
 *       the initial state for any {@code key_manager} without a registered
 *       {@code ProbeAdapter} (US-05/06/07 register their adapters when those Stories land).
 *       {@code db-tde} transitions to {@code ACTIVE} on the first successful write because its
 *       probe is registered in this Story.</li>
 * </ul>
 *
 * <p>Serializes to kebab-case strings per the DB contract
 * ({@code CHECK ('active','pending-spi')} — see V4 migration and AD-6 of feature-design).
 */
public enum ActivationStatus {

    ACTIVE("active"),
    PENDING_SPI("pending-spi");

    private final String value;

    ActivationStatus(String value) {
        this.value = value;
    }

    /**
     * Returns the kebab-case string value used in the DB contract and JSON responses.
     */
    public String getValue() {
        return value;
    }

    /**
     * Resolves an {@link ActivationStatus} from its kebab-case DB/JSON string representation.
     *
     * @param value the kebab-case string (e.g. {@code "active"} or {@code "pending-spi"})
     * @return the matching enum constant
     * @throws IllegalArgumentException if no constant matches
     */
    public static ActivationStatus fromValue(String value) {
        for (ActivationStatus status : values()) {
            if (status.value.equals(value)) {
                return status;
            }
        }
        throw new IllegalArgumentException("Unsupported activation_status: " + value);
    }
}
