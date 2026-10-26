package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.keymanager.domain.exception.HolderIsolationViolationException;
import com.eudistack.ebw.keymanager.domain.exception.InvalidCommitException;
import com.eudistack.ebw.keymanager.domain.exception.InvalidSignatureSubmissionException;
import com.eudistack.ebw.keymanager.domain.exception.OnboardingStateException;
import com.eudistack.ebw.keymanager.domain.exception.PrfSaltNotFoundException;
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
 * Exception handler scoped to {@link PasskeyPrfKeyManagerController}.
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
 *       → 403 opaque (ES-02 anti-probing — prevents DB tenants from inferring passkey-prf state).</li>
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
@RestControllerAdvice(assignableTypes = {PasskeyPrfKeyManagerController.class, PasskeyPrfOnboardingController.class})
public class PasskeyPrfKeyManagerExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(PasskeyPrfKeyManagerExceptionHandler.class);

    private static final String TYPE_BASE = "urn:eudistack:error:keymanager:passkey-prf:";
    private static final String PROP_ERROR = "error";
    private static final String INVALID_REQUEST = "invalid-request";

    @ExceptionHandler(WebExchangeBindException.class)
    public ResponseEntity<ProblemDetail> handleValidation(WebExchangeBindException ex) {
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        problem.setType(URI.create(TYPE_BASE + INVALID_REQUEST));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    @ExceptionHandler(UnsupportedCredentialFormatException.class)
    public ResponseEntity<ProblemDetail> handleUnsupportedFormat(UnsupportedCredentialFormatException ex) {
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        problem.setType(URI.create(TYPE_BASE + "unsupported-format"));
        problem.setProperty(PROP_ERROR, "unsupported_format");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    @ExceptionHandler(SignatureInvalidException.class)
    public ResponseEntity<ProblemDetail> handleSignatureInvalid(SignatureInvalidException ex) {
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        problem.setType(URI.create(TYPE_BASE + "signature-invalid"));
        problem.setProperty(PROP_ERROR, "signature_invalid");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    /**
     * ES-01 (EUDISTACK-536): submit step is malformed — unknown/expired {@code correlation_id}
     * or invalid base64url signature encoding. No cryptographic material is leaked in the body
     * (NFR-S-536-03).
     */
    @ExceptionHandler(InvalidSignatureSubmissionException.class)
    public ResponseEntity<ProblemDetail> handleInvalidSignatureSubmission(InvalidSignatureSubmissionException ex) {
        log.debug("keymanager.passkey-prf.invalid_signature_submission");
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        problem.setType(URI.create(TYPE_BASE + INVALID_REQUEST));
        problem.setProperty(PROP_ERROR, "invalid_request");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    /**
     * ES-02: opaque 403 — no body, no distinguishing detail between "tenant not found"
     * and "key_manager mode not PASSKEY_PRF" (anti-probing).
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
        problem.setType(URI.create(TYPE_BASE + INVALID_REQUEST));
        problem.setProperty(PROP_ERROR, "invalid_request");
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
        problem.setProperty(PROP_ERROR, "idempotency_replay");
        return ResponseEntity.status(HttpStatus.CONFLICT).body(problem);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleGeneral(Exception ex) {
        log.error("keymanager.passkey-prf.unhandled exception_class={}", ex.getClass().getName());
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.INTERNAL_SERVER_ERROR);
        problem.setType(URI.create(TYPE_BASE + "internal"));
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(problem);
    }

    /**
     * ES-02, ES-04 (EUDISTACK-537): PRF salt not found for the requested credential.
     * Maps to 404 with {@code error=wrap_handle_not_found} (architecture.md §8.3).
     * No {@code prf_salt} value is included in the response body (AC-06, NFR-S-537-01).
     */
    @ExceptionHandler(PrfSaltNotFoundException.class)
    public ResponseEntity<ProblemDetail> handlePrfSaltNotFound(PrfSaltNotFoundException ex) {
        log.debug("keymanager.passkey_prf.prf_salt_not_found credential_present=false");
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.NOT_FOUND);
        problem.setType(URI.create(TYPE_BASE + "wrap-handle-not-found"));
        problem.setProperty(PROP_ERROR, "wrap_handle_not_found");
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problem);
    }

    /**
     * AC-04, ES-04 (EUDISTACK-537): holder attempted to access a credential owned by a
     * different holder. Maps to 403 with {@code error=holder_isolation_violation}
     * (architecture.md §8.3).
     * No {@code prf_salt} value or owning {@code holder_id} is included in the response
     * body (AC-06, NFR-S-537-01, NFR-S-537-02).
     */
    @ExceptionHandler(HolderIsolationViolationException.class)
    public ResponseEntity<ProblemDetail> handleHolderIsolation(HolderIsolationViolationException ex) {
        log.debug("keymanager.passkey-prf.holder_isolation_violation");
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.FORBIDDEN);
        problem.setType(URI.create(TYPE_BASE + "holder-isolation-violation"));
        problem.setProperty(PROP_ERROR, "holder_isolation_violation");
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(problem);
    }
}
