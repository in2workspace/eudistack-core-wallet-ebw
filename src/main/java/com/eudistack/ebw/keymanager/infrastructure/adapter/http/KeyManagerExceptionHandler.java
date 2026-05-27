package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.keymanager.domain.exception.TenantWalletProfileUnsupportedException;
import com.eudistack.ebw.keymanager.domain.exception.UnsupportedCredentialFormatException;
import com.eudistack.ebw.keymanager.domain.exception.UnsupportedJwsAlgorithmException;
import com.eudistack.ebw.wallet.profile.domain.exception.TenantUnknownException;
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
import java.util.concurrent.TimeoutException;

/**
 * Exception handler scoped exclusively to {@link KeyManagerController}.
 *
 * <p>Handler mappings:
 * <ul>
 *   <li>{@link WebExchangeBindException} → 400 without field details (ES-01 — prevents
 *       probing of valid field names via error messages).
 *   <li>{@link UnsupportedCredentialFormatException} → 400 (AC-02).
 *   <li>{@link UnsupportedJwsAlgorithmException} → 422 (AC-03 / ADR-024).
 *   <li>{@link TenantWalletProfileUnsupportedException}, {@link TenantUnknownException}
 *       → 403 opaque with no body (ES-02 anti-probing — AD-119-2).
 *   <li>{@link TimeoutException} → 503 (ES-04 / NFR-P-119-01).
 *   <li>Any other {@link Exception} → 500.
 * </ul>
 *
 * <p>Scoped to {@link KeyManagerController} via {@code assignableTypes} to avoid
 * interfering with other EBW controllers (mirrors the pattern from
 * {@code WalletProfileQueryExceptionHandler}).
 * {@code @Order(HIGHEST_PRECEDENCE)} ensures this advice is evaluated before the
 * global {@code GlobalExceptionHandler} (which carries no explicit order and therefore
 * defaults to {@code LOWEST_PRECEDENCE}).</p>
 *
 * <p>Spec: EUDISTACK-119 ES-01, ES-02, ES-04, AC-02, AC-03.</p>
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

    /**
     * ES-02: opaque 403 — no body, no distinguishing detail between "tenant not found"
     * and "key_manager mode not supported" (anti-probing per AD-119-2).
     */
    @ExceptionHandler({TenantWalletProfileUnsupportedException.class, TenantUnknownException.class})
    public ResponseEntity<Void> handleForbidden(RuntimeException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }

    @ExceptionHandler(TimeoutException.class)
    public ResponseEntity<ProblemDetail> handleTimeout(TimeoutException ex) {
        log.warn("Key generation timed out (NFR-P-119-01)");
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.SERVICE_UNAVAILABLE);
        problem.setType(URI.create(TYPE_BASE + "service-unavailable"));
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(problem);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleGeneral(Exception ex) {
        log.error("Unhandled exception in KeyManagerController", ex);
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.INTERNAL_SERVER_ERROR);
        problem.setType(URI.create(TYPE_BASE + "internal"));
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(problem);
    }
}