package com.eudistack.ebw.infrastructure.error;

import com.eudistack.ebw.domain.model.exception.*;
import com.eudistack.ebw.wallet.config.domain.exception.ConfigInvariantViolationException;
import com.eudistack.ebw.wallet.config.domain.exception.ConfigVersionConflictException;
import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.support.WebExchangeBindException;
import org.springframework.web.method.annotation.HandlerMethodValidationException;

import java.net.URI;
import java.util.List;
import java.util.Map;

@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    // Auth exceptions — OAuth2 format for frontend compatibility
    // AC-002.2 / AC-002.4: both invalid and expired OTP return the same generic error
    @ExceptionHandler(UserAlreadyRegisteredException.class)
    public ResponseEntity<Map<String, String>> handleUserAlreadyRegistered(UserAlreadyRegisteredException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(Map.of("error", "user_already_registered", "message", ex.getMessage()));
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<Map<String, String>> handleUserNotFound(UserNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("error", "user_not_found", "message", ex.getMessage()));
    }

    @ExceptionHandler({InvalidOtpException.class, OtpExpiredException.class})
    public ResponseEntity<Map<String, String>> handleInvalidOrExpiredOtp(Exception ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "invalid_code", "message", "Invalid or expired verification code"));
    }

    @ExceptionHandler(TooManyAttemptsException.class)
    public ResponseEntity<Map<String, String>> handleTooManyAttempts(TooManyAttemptsException ex) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .body(Map.of("error", "too_many_attempts", "message", ex.getMessage()));
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<Map<String, String>> handleInvalidToken(InvalidTokenException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "invalid_token", "message", ex.getMessage()));
    }

    @ExceptionHandler(TokenFamilyCompromisedException.class)
    public ResponseEntity<Map<String, String>> handleTokenCompromised(TokenFamilyCompromisedException ex) {
        log.warn("Token family compromise detected");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "token_compromised", "message", ex.getMessage()));
    }

    // Resource exceptions — RFC 7807 ProblemDetail
    @ExceptionHandler(RateLimitExceededException.class)
    public ResponseEntity<ProblemDetail> handleRateLimit(RateLimitExceededException ex) {
        var problem = ProblemDetail.forStatusAndDetail(HttpStatus.TOO_MANY_REQUESTS, ex.getMessage());
        problem.setType(URI.create("urn:eudistack:error:rate-limit-exceeded"));
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header("Retry-After", String.valueOf(ex.getRetryAfterSeconds()))
                .body(problem);
    }

    @ExceptionHandler(PayloadTooLargeException.class)
    public ResponseEntity<ProblemDetail> handlePayloadTooLarge(PayloadTooLargeException ex) {
        var problem = ProblemDetail.forStatusAndDetail(HttpStatus.PAYLOAD_TOO_LARGE, ex.getMessage());
        problem.setType(URI.create("urn:eudistack:error:payload-too-large"));
        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE).body(problem);
    }

    @ExceptionHandler(PasskeyNotFoundException.class)
    public ResponseEntity<ProblemDetail> handlePasskeyNotFound(PasskeyNotFoundException ex) {
        var problem = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
        problem.setType(URI.create("urn:eudistack:error:passkey-not-found"));
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problem);
    }

    @ExceptionHandler(DuplicatePasskeyException.class)
    public ResponseEntity<ProblemDetail> handleDuplicatePasskey(DuplicatePasskeyException ex) {
        var problem = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, ex.getMessage());
        problem.setType(URI.create("urn:eudistack:error:duplicate-passkey"));
        return ResponseEntity.status(HttpStatus.CONFLICT).body(problem);
    }

    @ExceptionHandler(LastPasskeyException.class)
    public ResponseEntity<ProblemDetail> handleLastPasskey(LastPasskeyException ex) {
        var problem = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, ex.getMessage());
        problem.setType(URI.create("urn:eudistack:error:last-passkey"));
        return ResponseEntity.status(HttpStatus.CONFLICT).body(problem);
    }

    @ExceptionHandler(InvalidTransitionException.class)
    public ResponseEntity<ProblemDetail> handleInvalidTransition(InvalidTransitionException ex) {
        var problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNPROCESSABLE_ENTITY, ex.getMessage());
        problem.setType(URI.create("urn:eudistack:error:invalid-transition"));
        return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(problem);
    }

    @ExceptionHandler(CredentialNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleCredentialNotFound(CredentialNotFoundException ex) {
        var problem = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
        problem.setType(URI.create("urn:eudistack:error:credential-not-found"));
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problem);
    }

    @ExceptionHandler(UnsupportedFormatException.class)
    public ResponseEntity<ProblemDetail> handleUnsupportedFormat(UnsupportedFormatException ex) {
        var problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        problem.setType(URI.create("urn:eudistack:error:unsupported-format"));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    @ExceptionHandler(MalformedCredentialException.class)
    public ResponseEntity<ProblemDetail> handleMalformedCredential(MalformedCredentialException ex) {
        var problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        problem.setType(URI.create("urn:eudistack:error:malformed-credential"));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    @ExceptionHandler(ConfigInvariantViolationException.class)
    public ResponseEntity<ProblemDetail> handleConfigInvariantViolation(
            ConfigInvariantViolationException ex) {
        var problem = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, ex.getMessage());
        problem.setType(URI.create("urn:eudistack:error:config-invariant-violation"));
        problem.setTitle("Invariant violation");
        problem.setProperty("conflicting_field", ex.getConflictingField());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(problem);
    }

    @ExceptionHandler(ConfigVersionConflictException.class)
    public ResponseEntity<ProblemDetail> handleConfigVersionConflict(
            ConfigVersionConflictException ex) {
        var problem = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, ex.getMessage());
        problem.setType(URI.create("urn:eudistack:error:config-version-conflict"));
        problem.setTitle("Version conflict");
        problem.setProperty("expected_version", ex.getExpectedVersion());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(problem);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ProblemDetail> handleIllegalArgument(IllegalArgumentException ex) {
        var problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        problem.setType(URI.create("urn:eudistack:error:bad-request"));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    @ExceptionHandler(WebExchangeBindException.class)
    public ResponseEntity<ProblemDetail> handleValidation(WebExchangeBindException ex) {
        var violations = ex.getFieldErrors().stream()
                .map(fe -> Map.of("field", fe.getField(), "message", fe.getDefaultMessage() != null ? fe.getDefaultMessage() : "invalid"))
                .toList();
        var problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Validation failed");
        problem.setType(URI.create("urn:eudistack:error:validation-error"));
        problem.setProperty("violations", violations);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    // SEC-B1: a @Pattern/@NotBlank/... violation on a @PathVariable / @RequestParam / @RequestHeader
    // (e.g. an invalid schemaName on PUT /admin/wallet-tenant-config/{schemaName}) → 400, not 500.
    @ExceptionHandler({HandlerMethodValidationException.class, ConstraintViolationException.class})
    public ResponseEntity<ProblemDetail> handleMethodValidation(Exception ex) {
        var problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Validation failed");
        problem.setType(URI.create("urn:eudistack:error:validation-error"));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleGeneral(Exception ex) {
        log.error("Unhandled exception", ex);
        var problem = ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred");
        problem.setType(URI.create("urn:eudistack:error:internal"));
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(problem);
    }
}
