package com.eudistack.ebw.domain.model;

import java.time.Instant;

/**
 * Content of the new-device email (EUD-15 wireframes "Dispositivo nuevo", FR-08): any other device registered
 * in an account that already existed.
 *
 * @param registeredAt when the device was registered
 * @param deviceName   name the device was registered with
 * @param passkeyAdded a passkey was added in the same session to an account that already had one: the email
 *                     says so and replaces the new-passkey email (EUD-8 FR-10)
 * @param devicesUrl   "Dispositivos" of the Wallet App, {@code null} if the tenant has no {@code ebw.wallet_url}
 */
public record NewDeviceNotice(Instant registeredAt, String deviceName, boolean passkeyAdded, String devicesUrl) {
}
