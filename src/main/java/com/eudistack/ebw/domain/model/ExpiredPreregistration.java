package com.eudistack.ebw.domain.model;

import java.util.UUID;

/** A pre-registration deleted by the cleanup after it expired: what the audit trail needs, without the email. */
public record ExpiredPreregistration(UUID id, String requestedBy, boolean redeemed) {
}
