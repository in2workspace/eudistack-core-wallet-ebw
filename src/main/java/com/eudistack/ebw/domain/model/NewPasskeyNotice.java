package com.eudistack.ebw.domain.model;

import java.time.Instant;

/**
 * Content of the new-passkey email (EUD-8 wireframes "Passkey nueva", FR-10): sent only when the session that
 * added the passkey did not register a new device.
 *
 * @param addedAt    when the passkey was registered
 * @param devicesUrl "Dispositivos" of the Wallet App, {@code null} if the tenant has no {@code ebw.wallet_url}
 */
public record NewPasskeyNotice(Instant addedAt, String devicesUrl) {
}
