package com.eudistack.ebw.domain.model;

/** Result of a verified email code: the raw ticket and whether the account has passkeys. */
public record RegistrationTicketIssued(String ticket, long expiresIn, boolean hasPasskeys) {
}
