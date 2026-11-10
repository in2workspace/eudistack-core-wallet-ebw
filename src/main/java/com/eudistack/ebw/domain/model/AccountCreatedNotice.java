package com.eudistack.ebw.domain.model;

import java.time.Instant;

/**
 * Content of the new-account email of an account created with an onboarding ticket (design §2.6,
 * FR-29, EUD-8 wireframes "Cuenta nueva"). It does not name the system that requested the ticket
 * (EUD-315 decision P12): the audit trail keeps it.
 *
 * @param createdAt      when the account was created
 * @param deviceName     device the account was created on
 * @param disavowalUrl   single-use "it was not me" link
 * @param linkExpiresAt  when the link stops working
 */
public record AccountCreatedNotice(Instant createdAt, String deviceName, String disavowalUrl, Instant linkExpiresAt) {

    /** Never prints the link: it carries the single-use token. */
    @Override
    public String toString() {
        return "AccountCreatedNotice[createdAt=" + createdAt + ", deviceName=" + deviceName
                + ", disavowalUrl=[redacted], linkExpiresAt=" + linkExpiresAt + "]";
    }
}
