package com.eudistack.ebw.domain.model.exception;

/**
 * An audit entry that the audit API would reject: a reason outside the event type's vocabulary,
 * a reason that contradicts the result, or a missing resource. It is a programming error, not a
 * business failure.
 */
public class InvalidAuditEntryException extends RuntimeException {

    public InvalidAuditEntryException(String message) {
        super(message);
    }
}
