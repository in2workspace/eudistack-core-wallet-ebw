package com.eudistack.ebw.domain.model;

import java.time.Instant;

/**
 * Content of the email sent when a passkey is registered with an onboarding ticket (design §2.6,
 * FR-29, EUD-8 wireframes "Cuenta nueva"). It does not name the system that requested the ticket
 * (EUD-315 decision P12): the audit trail keeps it.
 *
 * @param createdAt      when the passkey was registered (the account was created, if it was)
 * @param deviceName     device the passkey was registered on
 * @param disavowalUrl   single-use "it was not me" link
 * @param linkExpiresAt  when the link stops working
 * @param accountCreated {@code true} if the ticket created the account, {@code false} if it already
 *                       existed: the email says so (EUD-315 decision P17, provisional texts)
 */
public record AccountCreatedNotice(Instant createdAt, String deviceName, String disavowalUrl, Instant linkExpiresAt,
                                   boolean accountCreated) {

    /** Never prints the link: it carries the single-use token. */
    @Override
    public String toString() {
        return "AccountCreatedNotice[createdAt=" + createdAt + ", deviceName=" + deviceName
                + ", disavowalUrl=[redacted], linkExpiresAt=" + linkExpiresAt + ", accountCreated=" + accountCreated
                + "]";
    }
}
