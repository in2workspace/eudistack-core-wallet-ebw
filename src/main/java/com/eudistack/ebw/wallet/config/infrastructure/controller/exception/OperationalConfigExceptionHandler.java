package com.eudistack.ebw.wallet.config.infrastructure.controller.exception;

import com.eudistack.ebw.wallet.config.application.operational.exception.IfMatchRequiredException;
import com.eudistack.ebw.wallet.config.application.operational.exception.IncompleteOperationalConfigException;
import com.eudistack.ebw.wallet.config.application.operational.exception.OperationalConfigNotFoundException;
import com.eudistack.ebw.wallet.config.application.operational.exception.ProbeFailedException;
import com.eudistack.ebw.wallet.config.application.operational.exception.UnsupportedKeyManagerException;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.kms.KmsAccessException;
import com.eudistack.ebw.wallet.config.infrastructure.controller.OperationalConfigController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.support.WebExchangeBindException;

import java.net.URI;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * RFC 9457 {@code ProblemDetail} exception handler scoped to {@link OperationalConfigController}.
 *
 * <p>Scoped with {@code assignableTypes} to avoid interfering with the global
 * {@code GlobalExceptionHandler}. Each mapping produces a {@link ProblemDetail} body with
 * a {@code urn:eudistack:error:...} type URI — no secret values are ever included in
 * any field (AC-2c, AC-4d, NFR-06).
 *
 * <p>HTTP status mapping (per tech-design §3.2 and TASKS.md task 8):
 * <ul>
 *   <li>{@link OperationalConfigNotFoundException} → {@code 404 Not Found}</li>
 *   <li>{@link IfMatchRequiredException} → {@code 428 Precondition Required}</li>
 *   <li>{@link IncompleteOperationalConfigException} → {@code 409 Conflict}</li>
 *   <li>{@link UnsupportedKeyManagerException} → {@code 409 Conflict}</li>
 *   <li>{@link ProbeFailedException} → {@code 424 Failed Dependency}</li>
 *   <li>{@link KmsAccessException} → {@code 424 Failed Dependency}</li>
 *   <li>{@link OptimisticLockingFailureException} → {@code 412 Precondition Failed}</li>
 *   <li>{@link IllegalArgumentException} (domain compact-ctor, ARN format, etc.) → {@code 400 Bad Request}</li>
 *   <li>{@link WebExchangeBindException} (Bean Validation) → {@code 400 Bad Request}</li>
 *   <li>Fallback {@link Exception} → {@code 500 Internal Server Error}</li>
 * </ul>
 */
@RestControllerAdvice(assignableTypes = OperationalConfigController.class)
public class OperationalConfigExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(OperationalConfigExceptionHandler.class);

    /**
     * Maps {@link OperationalConfigNotFoundException} to {@code 404 Not Found} (AC-5).
     */
    @ExceptionHandler(OperationalConfigNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleNotFound(OperationalConfigNotFoundException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
        problem.setType(URI.create("urn:eudistack:error:operational-config-not-found"));
        problem.setTitle("Not Found");
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problem);
    }

    /**
     * Maps {@link IfMatchRequiredException} to {@code 428 Precondition Required} (RFC 9457).
     */
    @ExceptionHandler(IfMatchRequiredException.class)
    public ResponseEntity<ProblemDetail> handleIfMatchRequired(IfMatchRequiredException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.PRECONDITION_REQUIRED, ex.getMessage());
        problem.setType(URI.create("urn:eudistack:error:precondition-required"));
        problem.setTitle("Precondition Required");
        return ResponseEntity.status(HttpStatus.PRECONDITION_REQUIRED).body(problem);
    }

    /**
     * Maps {@link IncompleteOperationalConfigException} to {@code 409 Conflict}.
     *
     * <p>The {@code detail} lists the missing <em>field names</em> only — never field values
     * (AC-4d). The list is safe for inclusion in the {@code ProblemDetail} body.
     */
    @ExceptionHandler(IncompleteOperationalConfigException.class)
    public ResponseEntity<ProblemDetail> handleIncompleteConfig(IncompleteOperationalConfigException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.CONFLICT,
                "Operational config is incomplete; missing or invalid fields: "
                        + String.join(", ", ex.invalidFields()));
        problem.setType(URI.create("urn:eudistack:error:incomplete-operational-config"));
        problem.setTitle("Incomplete Operational Configuration");
        problem.setProperty("invalid_fields", ex.invalidFields());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(problem);
    }

    /**
     * Maps {@link UnsupportedKeyManagerException} to {@code 409 Conflict}.
     *
     * <p>The response references the successor Stories without exposing infrastructure detail.
     */
    @ExceptionHandler(UnsupportedKeyManagerException.class)
    public ResponseEntity<ProblemDetail> handleUnsupportedKeyManager(UnsupportedKeyManagerException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.CONFLICT,
                "key_manager '" + ex.offendingKeyManager().getValue()
                        + "' is not supported in this release; see US-05/US-06/US-07 for HSM/QTSP/Hybrid support");
        problem.setType(URI.create("urn:eudistack:error:unsupported-key-manager"));
        problem.setTitle("Unsupported Key Manager");
        problem.setProperty("key_manager", ex.offendingKeyManager().getValue());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(problem);
    }

    /**
     * Maps {@link ProbeFailedException} to {@code 424 Failed Dependency}.
     *
     * <p>The {@link ProbeFailedException#reason()} is a functional description safe for
     * external exposure — it never contains raw KMS error bodies or secret material.
     */
    @ExceptionHandler(ProbeFailedException.class)
    public ResponseEntity<ProblemDetail> handleProbeFailed(ProbeFailedException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.FAILED_DEPENDENCY,
                "Key-manager connectivity probe failed: " + ex.reason());
        problem.setType(URI.create("urn:eudistack:error:probe-failed"));
        problem.setTitle("Key Manager Connectivity Probe Failed");
        problem.setProperty("reason", ex.reason());
        return ResponseEntity.status(HttpStatus.FAILED_DEPENDENCY).body(problem);
    }

    /**
     * Maps {@link KmsAccessException} to {@code 424 Failed Dependency}.
     *
     * <p>{@link KmsAccessException} wraps infrastructure KMS errors with a functional
     * message — raw AWS error bodies are never propagated.
     */
    @ExceptionHandler(KmsAccessException.class)
    public ResponseEntity<ProblemDetail> handleKmsAccess(KmsAccessException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.FAILED_DEPENDENCY,
                "KMS access failed: " + ex.getMessage());
        problem.setType(URI.create("urn:eudistack:error:kms-access-failed"));
        problem.setTitle("KMS Access Failed");
        return ResponseEntity.status(HttpStatus.FAILED_DEPENDENCY).body(problem);
    }

    /**
     * Maps {@link OptimisticLockingFailureException} to {@code 412 Precondition Failed}.
     *
     * <p>Occurs when the {@code If-Match} version in a PUT request no longer matches the
     * stored {@code version} — concurrent update scenario (AC-5e, E-7).
     */
    @ExceptionHandler(OptimisticLockingFailureException.class)
    public ResponseEntity<ProblemDetail> handleOptimisticLocking(OptimisticLockingFailureException ex) {
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.PRECONDITION_FAILED);
        problem.setType(URI.create("urn:eudistack:error:optimistic-lock-failed"));
        problem.setTitle("Precondition Failed");
        problem.setDetail(
                "The If-Match version no longer matches the current version; "
                        + "read the current version and retry with the new If-Match value.");
        return ResponseEntity.status(HttpStatus.PRECONDITION_FAILED).body(problem);
    }

    /**
     * Maps {@link IllegalArgumentException} to {@code 400 Bad Request}.
     *
     * <p>Covers domain compact-constructor failures (e.g. malformed ARN, unsupported algorithm,
     * empty {@code wrappedDek}) and invalid {@code If-Match} header format.
     * The exception message is safe for external exposure: domain compact constructors
     * produce functional messages without secret values.
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ProblemDetail> handleIllegalArgument(IllegalArgumentException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.BAD_REQUEST, ex.getMessage());
        problem.setType(URI.create("urn:eudistack:error:bad-request"));
        problem.setTitle("Bad Request");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    /**
     * Maps {@link WebExchangeBindException} (Bean Validation failures) to {@code 400 Bad Request}.
     *
     * <p>Lists the field constraint violations without exposing the rejected values
     * (field names only in the {@code violations} property).
     */
    @ExceptionHandler(WebExchangeBindException.class)
    public ResponseEntity<ProblemDetail> handleValidation(WebExchangeBindException ex) {
        var violations = ex.getFieldErrors().stream()
                .map(fe -> Map.of(
                        "field", fe.getField(),
                        "message", fe.getDefaultMessage() != null ? fe.getDefaultMessage() : "invalid"))
                .collect(Collectors.toList());
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.BAD_REQUEST, "Validation failed");
        problem.setType(URI.create("urn:eudistack:error:validation-error"));
        problem.setTitle("Validation Error");
        problem.setProperty("violations", violations);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    /**
     * Fallback handler — catches any unexpected exception and returns {@code 500}.
     *
     * <p>Logs the full stack trace with the correlation id (if available in the exception message)
     * but returns only a safe, generic message to the caller. No stack trace or internal detail
     * is ever included in the response body (NFR-06).
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleGeneral(Exception ex) {
        log.error("Unhandled exception in OperationalConfigController", ex);
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An unexpected error occurred; check the correlation_id in server logs for details.");
        problem.setType(URI.create("urn:eudistack:error:internal"));
        problem.setTitle("Internal Server Error");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(problem);
    }
}
