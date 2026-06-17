package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.keymanager.domain.exception.SignatureInvalidException;
import com.eudistack.ebw.keymanager.domain.exception.TenantWalletProfileUnsupportedException;
import com.eudistack.ebw.keymanager.domain.exception.UnsupportedCredentialFormatException;
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

/**
 * Exception handler scoped to {@link HybridKeyManagerController}.
 *
 * <p>Handler mappings:
 * <ul>
 *   <li>{@link WebExchangeBindException} → 400 without field details (ES-01 — prevents
 *       probing of valid field names via error messages).</li>
 *   <li>{@link UnsupportedCredentialFormatException} → 400 with {@code error=unsupported_format}
 *       (AC-05, ES-01 — format not in the allow-list {vc+sd-jwt, jwt_vc_json}).</li>
 *   <li>{@link SignatureInvalidException} → 400 with {@code error=signature_invalid}
 *       (ES-03 — structurally invalid or mismatched client assertion).</li>
 *   <li>{@link TenantWalletProfileUnsupportedException}, {@link TenantUnknownException}
 *       → 403 opaque (ES-02 anti-probing — prevents DB tenants from inferring hybrid state).</li>
 *   <li>Any other {@link Exception} → 500 (catch-all, class name only to prevent leakage).</li>
 * </ul>
 *
 * <p>Spec: EUDISTACK-533 AC-03, AC-04, AC-05, ES-01, ES-03; architecture.md §8.3.</p>
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice(assignableTypes = HybridKeyManagerController.class)
public class HybridKeyManagerExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(HybridKeyManagerExceptionHandler.class);

    private static final String TYPE_BASE = "urn:eudistack:error:keymanager:hybrid:";

    @ExceptionHandler(WebExchangeBindException.class)
    public ResponseEntity<ProblemDetail> handleValidation(WebExchangeBindException ex) {
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        problem.setType(URI.create(TYPE_BASE + "invalid-request"));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    @ExceptionHandler(UnsupportedCredentialFormatException.class)
    public ResponseEntity<ProblemDetail> handleUnsupportedFormat(UnsupportedCredentialFormatException ex) {
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        problem.setType(URI.create(TYPE_BASE + "unsupported-format"));
        problem.setProperty("error", "unsupported_format");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    @ExceptionHandler(SignatureInvalidException.class)
    public ResponseEntity<ProblemDetail> handleSignatureInvalid(SignatureInvalidException ex) {
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        problem.setType(URI.create(TYPE_BASE + "signature-invalid"));
        problem.setProperty("error", "signature_invalid");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    /**
     * ES-02: opaque 403 — no body, no distinguishing detail between "tenant not found"
     * and "key_manager mode not HYBRID" (anti-probing).
     */
    @ExceptionHandler({TenantWalletProfileUnsupportedException.class, TenantUnknownException.class})
    public ResponseEntity<Void> handleForbidden(RuntimeException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleGeneral(Exception ex) {
        log.error("keymanager.hybrid.unhandled exception_class={}", ex.getClass().getName());
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.INTERNAL_SERVER_ERROR);
        problem.setType(URI.create(TYPE_BASE + "internal"));
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(problem);
    }
}
