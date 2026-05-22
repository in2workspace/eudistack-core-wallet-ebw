package com.eudistack.ebw.wallet.profile.infrastructure.web;

import com.eudistack.ebw.wallet.profile.domain.exception.TenantUnknownException;
import com.eudistack.ebw.wallet.profile.infrastructure.observability.WalletProfileQueryTelemetry;
import com.eudistack.ebw.wallet.profile.infrastructure.web.dto.ErrorResponse;
import io.r2dbc.spi.R2dbcException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Exception handler scoped exclusively to {@link WalletProfileQueryController}.
 *
 * <p>All error paths emit the mandatory security and cache headers (NFR-08 / NFR-S-413-03):
 * <ul>
 *   <li>{@code Cache-Control: public, max-age=60, must-revalidate}
 *   <li>{@code X-Content-Type-Options: nosniff}
 *   <li>{@code Referrer-Policy: no-referrer}
 * </ul>
 *
 * <p>The 404 body is always the same opaque {@code {"error":"tenant_unknown"}} regardless of
 * the internal cause, guaranteeing byte-exact equality across all three anti-enumeration paths
 * (AC-04/AC-05/AC-08 — AD-413-2). The single private method {@link #buildOpaque404Response()}
 * is the only construction point, making divergence mechanically impossible.
 *
 * <p>Handler mappings:
 * <ul>
 *   <li>{@link TenantUnknownException} → 404 opaque.
 *   <li>{@link IllegalArgumentException} → 500 {@code internal_error} (domain validation
 *       defense-in-depth, ES-03).
 *   <li>{@link R2dbcException} and subclasses → 503 {@code service_unavailable} (ES-04/ES-05).
 *   <li>Any other {@link Throwable} → 500 {@code internal_error}.
 * </ul>
 *
 * <p>Scope is limited to {@link WalletProfileQueryController} via
 * {@code assignableTypes} to avoid interfering with other EBW controllers (R-413-2).
 *
 * <p>See technical-design.md §3.5 AD-413-2/AD-413-4 and acceptance-criteria.md
 * AC-04/AC-05/AC-06/AC-08/ES-03/ES-04/ES-05.
 */
@RestControllerAdvice(assignableTypes = WalletProfileQueryController.class)
public class WalletProfileQueryExceptionHandler {

    private static final String HEADER_CACHE_CONTROL = "Cache-Control";
    private static final String HEADER_CACHE_CONTROL_VALUE = "public, max-age=60, must-revalidate";
    private static final String HEADER_X_CONTENT_TYPE_OPTIONS = "X-Content-Type-Options";
    private static final String HEADER_X_CONTENT_TYPE_OPTIONS_VALUE = "nosniff";
    private static final String HEADER_REFERRER_POLICY = "Referrer-Policy";
    private static final String HEADER_REFERRER_POLICY_VALUE = "no-referrer";

    private final WalletProfileQueryTelemetry telemetry;

    public WalletProfileQueryExceptionHandler(WalletProfileQueryTelemetry telemetry) {
        this.telemetry = telemetry;
    }

    /**
     * Handles all three opaque 404 paths (AC-04, AC-05, AC-08).
     *
     * <p>The internal {@code reason} is logged by telemetry but is never included in the
     * response body (byte-exact anti-enumeration — AD-413-2).
     */
    @ExceptionHandler(TenantUnknownException.class)
    public ResponseEntity<ErrorResponse> handleTenantUnknown(TenantUnknownException ex) {
        long startNanos = System.nanoTime();
        telemetry.recordNotFound("unknown", ex.getReason(), startNanos);
        return buildOpaque404Response();
    }

    /**
     * Handles domain validation failures from the compact constructor (ES-03).
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgument(IllegalArgumentException ex) {
        long startNanos = System.nanoTime();
        telemetry.recordError("unknown", ex, startNanos);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .headers(securityAndCacheHeaders())
                .contentType(MediaType.APPLICATION_JSON)
                .body(ErrorResponse.INTERNAL_ERROR);
    }

    /**
     * Handles R2DBC connection/timeout errors (ES-04/ES-05) — maps to 503.
     */
    @ExceptionHandler(R2dbcException.class)
    public ResponseEntity<ErrorResponse> handleR2dbcException(R2dbcException ex) {
        long startNanos = System.nanoTime();
        telemetry.recordError("unknown", ex, startNanos);
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .headers(securityAndCacheHeaders())
                .contentType(MediaType.APPLICATION_JSON)
                .body(ErrorResponse.SERVICE_UNAVAILABLE);
    }

    /**
     * Catch-all for any unexpected throwable — maps to 500.
     */
    @ExceptionHandler(Throwable.class)
    public ResponseEntity<ErrorResponse> handleThrowable(Throwable ex) {
        long startNanos = System.nanoTime();
        telemetry.recordError("unknown", ex, startNanos);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .headers(securityAndCacheHeaders())
                .contentType(MediaType.APPLICATION_JSON)
                .body(ErrorResponse.INTERNAL_ERROR);
    }

    /**
     * Single construction point for the opaque 404 response (AD-413-2).
     *
     * <p>All three anti-enumeration paths call this method, guaranteeing byte-exact equality
     * of body and headers across AC-04, AC-05, and AC-08.
     */
    private ResponseEntity<ErrorResponse> buildOpaque404Response() {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .headers(securityAndCacheHeaders())
                .contentType(MediaType.APPLICATION_JSON)
                .body(ErrorResponse.TENANT_UNKNOWN);
    }

    private HttpHeaders securityAndCacheHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HEADER_CACHE_CONTROL, HEADER_CACHE_CONTROL_VALUE);
        headers.set(HEADER_X_CONTENT_TYPE_OPTIONS, HEADER_X_CONTENT_TYPE_OPTIONS_VALUE);
        headers.set(HEADER_REFERRER_POLICY, HEADER_REFERRER_POLICY_VALUE);
        return headers;
    }
}
