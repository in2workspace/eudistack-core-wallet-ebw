package com.eudistack.ebw.wallet.profile.domain.exception;

/**
 * Domain exception thrown when the current tenant cannot be resolved or has no
 * wallet profile seeded.
 *
 * <p>Used for all three opaque-404 paths (AD-413-2 — byte-exact anti-enumeration):
 * <ul>
 *   <li>{@code tenant_absent_from_context} — the Reactor Context carries no
 *       {@code TENANT_DOMAIN} key (host malformed or filter did not set it).
 *   <li>{@code profile_not_seeded} — the port returned {@code Mono.empty()} because
 *       no {@code tenant_wallet_profile} row exists for the resolved tenant.
 * </ul>
 *
 * <p>The {@code reason} field is recorded in the structured log and OTEL span but is
 * <em>never</em> surfaced to the caller; the HTTP response body is always the same
 * opaque {@code {"error":"tenant_unknown"}} (NFR-08).
 *
 * <p>See technical-design.md §3.5 AD-413-2 and acceptance-criteria.md AC-04/AC-05/AC-08.
 */
public class TenantUnknownException extends RuntimeException {

    /**
     * The internal reason for the failure — logged but not sent to the caller.
     */
    public enum Reason {
        TENANT_ABSENT_FROM_CONTEXT,
        PROFILE_NOT_SEEDED
    }

    private final Reason reason;

    public TenantUnknownException(Reason reason) {
        super("tenant_unknown");
        this.reason = reason;
    }

    public Reason getReason() {
        return reason;
    }
}
