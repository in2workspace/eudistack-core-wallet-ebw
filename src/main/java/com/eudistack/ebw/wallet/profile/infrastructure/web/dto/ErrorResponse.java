package com.eudistack.ebw.wallet.profile.infrastructure.web.dto;

/**
 * HTTP error response DTO used by {@code WalletProfileQueryExceptionHandler}.
 *
 * <p>The {@code error} field carries a machine-readable code. Permitted values:
 * <ul>
 *   <li>{@code "tenant_unknown"} — 404 opaque response for all three anti-enumeration paths
 *       (AC-04, AC-05, AC-08 — AD-413-2).
 *   <li>{@code "internal_error"} — 500 for unexpected domain validation failures (ES-03).
 *   <li>{@code "service_unavailable"} — 503 for R2DBC connection/timeout errors (ES-04/ES-05).
 * </ul>
 *
 * <p>No message field is included; the response body is intentionally minimal to avoid
 * leaking implementation detail (NFR-08).
 *
 * <p>See technical-design.md §3.2 (DTO row) and acceptance-criteria.md ES-03/ES-04/ES-05.
 */
public record ErrorResponse(String error) {

    /** Opaque 404 body — used for all three 404 paths (byte-exact, AD-413-2). */
    public static final ErrorResponse TENANT_UNKNOWN = new ErrorResponse("tenant_unknown");

    /** 500 body for domain validation errors (ES-03). */
    public static final ErrorResponse INTERNAL_ERROR = new ErrorResponse("internal_error");

    /** 503 body for R2DBC infrastructure failures (ES-04/ES-05). */
    public static final ErrorResponse SERVICE_UNAVAILABLE = new ErrorResponse("service_unavailable");
}
