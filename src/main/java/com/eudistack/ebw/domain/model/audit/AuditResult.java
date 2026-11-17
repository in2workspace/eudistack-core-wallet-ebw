package com.eudistack.ebw.domain.model.audit;

/**
 * Outcome of an audited fact, as defined by the audit event catalogue
 * ({@code result_semantics}): completed, evaluated and refused, or not completable.
 */
public enum AuditResult {
    SUCCESS,
    DENIED,
    FAILURE
}
