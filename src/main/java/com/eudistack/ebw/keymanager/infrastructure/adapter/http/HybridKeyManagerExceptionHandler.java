package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.keymanager.domain.exception.InvalidCommitException;
import com.eudistack.ebw.keymanager.domain.exception.OnboardingStateException;
import com.eudistack.ebw.keymanager.domain.exception.SignatureInvalidException;
import com.eudistack.ebw.keymanager.domain.exception.TenantWalletProfileUnsupportedException;
import com.eudistack.ebw.keymanager.domain.exception.UnsupportedCredentialFormatException;
import com.eudistack.ebw.keymanager.domain.exception.PrfUnsupportedException;
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
 * <p>Additional mappings for EUDISTACK-534 (onboarding endpoints):
 * <ul>
 *   <li>{@link InvalidCommitException} → 400 with {@code error=invalid_request}
 *       (ES-01 — byte-length invariants, private key in cnf_jwk).</li>
 *   <li>{@link OnboardingStateException} → 409 with {@code error=idempotency_replay}
 *       (ES-03 — different blob for same holder+credential, or PRF salt missing).</li>
 * </ul>
 *
 * <p>Spec: EUDISTACK-533 AC-03, AC-04, AC-05, ES-01, ES-03;
 *          EUDISTACK-534 ES-01, ES-02, ES-03; architecture.md §8.3.</p>
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice(assignableTypes = {HybridKeyManagerController.class, HybridOnboardingController.class})
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

    /**
     * ES-01 (EUDISTACK-534): structurally invalid commit — byte lengths wrong or
     * {@code cnf_jwk} contains the private key parameter {@code "d"}.
     */
    @ExceptionHandler(InvalidCommitException.class)
    public ResponseEntity<ProblemDetail> handleInvalidCommit(InvalidCommitException ex) {
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        problem.setType(URI.create(TYPE_BASE + "invalid-request"));
        problem.setProperty("error", "invalid_request");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    /**
     * ES-03 (EUDISTACK-534): onboarding state conflict — different blob for same
     * {@code (holderId, credentialId)}, missing PRF salt, or concurrent duplicate.
     */
    @ExceptionHandler(OnboardingStateException.class)
    public ResponseEntity<ProblemDetail> handleOnboardingState(OnboardingStateException ex) {
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.CONFLICT);
        problem.setType(URI.create(TYPE_BASE + "idempotency-replay"));
        problem.setProperty("error", "idempotency_replay");
        return ResponseEntity.status(HttpStatus.CONFLICT).body(problem);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleGeneral(Exception ex) {
        log.error("keymanager.hybrid.unhandled exception_class={}", ex.getClass().getName());
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.INTERNAL_SERVER_ERROR);
        problem.setType(URI.create(TYPE_BASE + "internal"));
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(problem);
    }

    @ExceptionHandler(PrfUnsupportedException.class)
    public ResponseEntity<ProblemDetail> handlePrfUnsupported(
            PrfUnsupportedException ex) {
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.UNPROCESSABLE_ENTITY);
        problem.setType(URI.create(TYPE_BASE + "prf-unsupported"));
        problem.setProperty("error", "prf_unsupported");
        return ResponseEntity
                .status(HttpStatus.UNPROCESSABLE_ENTITY)
                .body(problem);
    }
}
