package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.keymanager.domain.exception.InvalidConsumerOriginException;
import com.eudistack.ebw.keymanager.domain.exception.InvalidKeyIdFormatException;
import com.eudistack.ebw.keymanager.domain.exception.KeyAccessDeniedException;
import com.eudistack.ebw.keymanager.domain.exception.SigningTypeFormatMismatchException;
import com.eudistack.ebw.keymanager.domain.exception.TenantWalletProfileUnsupportedException;
import com.eudistack.ebw.keymanager.domain.exception.UnsupportedCredentialFormatException;
import com.eudistack.ebw.keymanager.domain.exception.UnsupportedJwsAlgorithmException;
import com.eudistack.ebw.keymanager.domain.exception.UnsupportedSigningTypeException;
import com.eudistack.ebw.wallet.profile.domain.exception.TenantUnknownException;
import io.r2dbc.spi.R2dbcNonTransientResourceException;
import io.r2dbc.spi.R2dbcTimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.support.WebExchangeBindException;

import java.net.URI;
import java.util.Map;
import java.util.concurrent.TimeoutException;

/**
 * Exception handler scoped to {@link KeyManagerController}.
 *
 * <p>Handler mappings:
 * <ul>
 *   <li>{@link WebExchangeBindException} → 400 without field details (ES-01 — prevents
 *       probing of valid field names via error messages).</li>
 *   <li>{@link InvalidKeyIdFormatException} → 400 (W2 — malformed UUID keyId).</li>
 *   <li>{@link InvalidConsumerOriginException} → 400 (F3 — present but unrecognised
 *       {@code X-Consumer-Origin} header value).</li>
 *   <li>{@link UnsupportedCredentialFormatException} → 400 (AC-02).</li>
 *   <li>{@link UnsupportedJwsAlgorithmException} → 422 (AC-03 / ADR-024).</li>
 *   <li>{@link UnsupportedSigningTypeException} → 400 (AC-03 EUDISTACK-407).</li>
 *   <li>{@link SigningTypeFormatMismatchException} → 400 (AC-04 EUDISTACK-407 — only if
 *       the exception escapes the opaque-reject path; included for completeness).</li>
 *   <li>{@link KeyAccessDeniedException} → 401 with opaque body (AC-06 / ADR-025).</li>
 *   <li>{@link TenantWalletProfileUnsupportedException}, {@link TenantUnknownException}
 *       → 403 opaque with no body (ES-02 anti-probing — AD-119-2).</li>
 *   <li>{@link R2dbcTimeoutException}, {@link R2dbcNonTransientResourceException} → 503
 *       (ES-04 DB unavailable — EUDISTACK-407).</li>
 *   <li>{@link TimeoutException} → 503 (ES-05 signing timeout — NFR-S-407-07).</li>
 *   <li>Any other {@link Exception} → 500.</li>
 * </ul>
 *
 * <p>IMPORTANT: The {@link KeyAccessDeniedException} handler NEVER exposes the
 * {@code internalReason} in the HTTP response. The body is always the opaque
 * {@code {"error": "KeyAccessDenied"}} (ADR-025).</p>
 *
 * <p>{@code @Order(HIGHEST_PRECEDENCE)} ensures this advice is evaluated before the global
 * {@code GlobalExceptionHandler}.</p>
 *
 * <p>Spec: EUDISTACK-119, EUDISTACK-407, ADR-025.</p>
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice(assignableTypes = KeyManagerController.class)
public class KeyManagerExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(KeyManagerExceptionHandler.class);

    private static final String TYPE_BASE = "urn:eudistack:error:keymanager:";

    @ExceptionHandler(WebExchangeBindException.class)
    public ResponseEntity<ProblemDetail> handleValidation(WebExchangeBindException ex) {
        // ES-01: return 400 without field details to prevent field-name probing
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        problem.setType(URI.create(TYPE_BASE + "invalid-request"));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    /**
     * W2: malformed UUID in the {@code keyId} path variable → 400.
     * Returns 400, not 401, so clients can distinguish a format error from an access denial.
     */
    @ExceptionHandler(InvalidKeyIdFormatException.class)
    public ResponseEntity<ProblemDetail> handleInvalidKeyIdFormat(InvalidKeyIdFormatException ex) {
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        problem.setType(URI.create(TYPE_BASE + "invalid-key-id"));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    /**
     * F3: {@code X-Consumer-Origin} header present but contains an unrecognised value → 400.
     */
    @ExceptionHandler(InvalidConsumerOriginException.class)
    public ResponseEntity<ProblemDetail> handleInvalidConsumerOrigin(InvalidConsumerOriginException ex) {
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        problem.setType(URI.create(TYPE_BASE + "invalid-consumer-origin"));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    @ExceptionHandler(UnsupportedCredentialFormatException.class)
    public ResponseEntity<ProblemDetail> handleUnsupportedFormat(UnsupportedCredentialFormatException ex) {
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        problem.setType(URI.create(TYPE_BASE + "unsupported-format"));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    @ExceptionHandler(UnsupportedJwsAlgorithmException.class)
    public ResponseEntity<ProblemDetail> handleUnsupportedAlgorithm(UnsupportedJwsAlgorithmException ex) {
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.UNPROCESSABLE_ENTITY);
        problem.setType(URI.create(TYPE_BASE + "unsupported-algorithm"));
        return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(problem);
    }

    // --- EUDISTACK-407 additions ---

    @ExceptionHandler(UnsupportedSigningTypeException.class)
    public ResponseEntity<ProblemDetail> handleUnsupportedSigningType(UnsupportedSigningTypeException ex) {
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        problem.setType(URI.create(TYPE_BASE + "unsupported-signing-type"));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    @ExceptionHandler(SigningTypeFormatMismatchException.class)
    public ResponseEntity<ProblemDetail> handleSigningTypeMismatch(SigningTypeFormatMismatchException ex) {
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        problem.setType(URI.create(TYPE_BASE + "signing-type-format-mismatch"));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    /**
     * AC-06 / ADR-025: opaque 401 — body is ALWAYS identical regardless of the internal reason.
     * The {@code internalReason} from {@link KeyAccessDeniedException#getInternalReason()} is
     * NEVER included here.
     */
    @ExceptionHandler(KeyAccessDeniedException.class)
    public ResponseEntity<Map<String, String>> handleKeyAccessDenied(KeyAccessDeniedException ex) {
        // Log at debug (internal reason is for audit, not for application logs in prod)
        log.debug("keymanager.sign.rejected internal_reason={}", ex.getInternalReason());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "KeyAccessDenied"));
    }

    /**
     * ES-02 / AD-119-2: opaque 403 — no body, no distinguishing detail between
     * "tenant not found" and "key_manager mode not supported" (anti-probing).
     */
    @ExceptionHandler({TenantWalletProfileUnsupportedException.class, TenantUnknownException.class})
    public ResponseEntity<Void> handleForbidden(RuntimeException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }

    /**
     * ES-04: DB unavailable during signing — maps to 503 Service Unavailable.
     *
     * <p>F5: logs only the exception class (not the full message or stack trace) to prevent
     * potential credential / query leakage from DB error text.</p>
     */
    @ExceptionHandler({R2dbcTimeoutException.class, R2dbcNonTransientResourceException.class})
    public ResponseEntity<ProblemDetail> handleDbUnavailable(Exception ex) {
        log.error("keymanager.sign.db_unavailable exception_class={}", ex.getClass().getName());
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.SERVICE_UNAVAILABLE);
        problem.setType(URI.create(TYPE_BASE + "service-unavailable"));
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(problem);
    }

    /**
     * ES-05 / NFR-S-407-07: signing timeout kill-switch — maps to 503.
     */
    @ExceptionHandler(TimeoutException.class)
    public ResponseEntity<ProblemDetail> handleTimeout(TimeoutException ex) {
        log.warn("keymanager.sign.timeout");
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.SERVICE_UNAVAILABLE);
        problem.setType(URI.create(TYPE_BASE + "service-unavailable"));
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(problem);
    }

    /**
     * F5: catch-all logs only the exception class, not the full stack trace or message,
     * to prevent accidental leakage of sensitive data present in exception messages.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleGeneral(Exception ex) {
        log.error("keymanager.unhandled exception_class={}", ex.getClass().getName());
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.INTERNAL_SERVER_ERROR);
        problem.setType(URI.create(TYPE_BASE + "internal"));
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(problem);
    }
}
