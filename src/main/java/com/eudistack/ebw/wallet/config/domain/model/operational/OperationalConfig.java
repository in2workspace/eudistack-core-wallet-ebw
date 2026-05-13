package com.eudistack.ebw.wallet.config.domain.model.operational;

/**
 * Sealed domain value object representing the operational configuration for a server-mode tenant.
 *
 * <p>Each permitted subtype corresponds to a specific key-manager variant (FR-10, AD-3 of
 * feature-design). Only {@link DbTdeOperationalConfig} is implemented in US-03 (EUDISTACK-414);
 * the remaining subtypes will be added by US-05 (EUDISTACK-416 — HSM), US-06 (EUDISTACK-417 —
 * QTSP) and US-07 (EUDISTACK-418 — Hybrid) when those Stories are delivered.
 *
 * <p>The {@code permits} clause is intentionally limited to {@code DbTdeOperationalConfig} in
 * this Story (approved pragmatic deviation — YAGNI; expanding {@code permits} requires all listed
 * classes to exist at compile time).
 *
 * <p>Implementations must be immutable records. No framework or infrastructure imports allowed
 * in this package.
 */
public sealed interface OperationalConfig permits DbTdeOperationalConfig {
}
