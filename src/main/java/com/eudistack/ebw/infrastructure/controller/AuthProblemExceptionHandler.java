package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.domain.model.exception.AuthenticationFailedException;
import com.eudistack.ebw.domain.model.exception.InvalidOtpException;
import com.eudistack.ebw.domain.model.exception.InvalidSessionException;
import com.eudistack.ebw.domain.model.exception.InvalidTicketException;
import com.eudistack.ebw.domain.model.exception.OtpExpiredException;
import com.eudistack.ebw.domain.model.exception.PasskeyPrfUnsupportedException;
import com.eudistack.ebw.domain.model.exception.RateLimitExceededException;
import com.eudistack.ebw.domain.model.exception.RegistrationFailedException;
import com.eudistack.ebw.domain.model.exception.TenantConfigMissingException;
import com.eudistack.ebw.domain.model.exception.TooManyAttemptsException;
import com.eudistack.ebw.domain.model.exception.UnknownCredentialException;
import com.eudistack.ebw.infrastructure.controller.support.AuthProblems;
import com.eudistack.ebw.infrastructure.controller.support.RefreshCookies;
import com.eudistack.ebw.infrastructure.controller.support.WalletRequestHeader.MissingWalletRequestHeaderException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ServerWebInputException;

/**
 * Errors of the registration and access API as RFC 9457 {@code application/problem+json}, with
 * the contract code in {@code type}. Scoped to its controllers: the other controllers keep their
 * error formats. Never reveals the concrete verification failure (that goes to the logs).
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice(assignableTypes = {AuthController.class, PasskeyRegistrationController.class,
        SessionController.class})
public class AuthProblemExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(AuthProblemExceptionHandler.class);

    private final RefreshCookies refreshCookies;

    public AuthProblemExceptionHandler(RefreshCookies refreshCookies) {
        this.refreshCookies = refreshCookies;
    }

    @ExceptionHandler(ServerWebInputException.class)
    public ResponseEntity<ProblemDetail> handleInvalidRequest(ServerWebInputException ex) {
        return problem(HttpStatus.BAD_REQUEST, AuthProblems.INVALID_REQUEST);
    }

    @ExceptionHandler(InvalidOtpException.class)
    public ResponseEntity<ProblemDetail> handleInvalidCode(InvalidOtpException ex) {
        return problem(HttpStatus.UNAUTHORIZED, AuthProblems.INVALID_CODE);
    }

    @ExceptionHandler(OtpExpiredException.class)
    public ResponseEntity<ProblemDetail> handleExpiredCode(OtpExpiredException ex) {
        return problem(HttpStatus.UNAUTHORIZED, AuthProblems.EXPIRED_CODE);
    }

    @ExceptionHandler(TooManyAttemptsException.class)
    public ResponseEntity<ProblemDetail> handleTooManyAttempts(TooManyAttemptsException ex) {
        return problem(HttpStatus.TOO_MANY_REQUESTS, AuthProblems.TOO_MANY_ATTEMPTS);
    }

    @ExceptionHandler(RateLimitExceededException.class)
    public ResponseEntity<ProblemDetail> handleRateLimited(RateLimitExceededException ex) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .header(HttpHeaders.RETRY_AFTER, String.valueOf(ex.getRetryAfterSeconds()))
                .body(AuthProblems.of(HttpStatus.TOO_MANY_REQUESTS, AuthProblems.RATE_LIMITED));
    }

    @ExceptionHandler(InvalidTicketException.class)
    public ResponseEntity<ProblemDetail> handleInvalidTicket(InvalidTicketException ex) {
        return problem(HttpStatus.UNAUTHORIZED, AuthProblems.INVALID_TICKET);
    }

    @ExceptionHandler(RegistrationFailedException.class)
    public ResponseEntity<ProblemDetail> handleRegistrationFailed(RegistrationFailedException ex) {
        return problem(HttpStatus.BAD_REQUEST, AuthProblems.REGISTRATION_FAILED);
    }

    @ExceptionHandler(PasskeyPrfUnsupportedException.class)
    public ResponseEntity<ProblemDetail> handlePrfUnsupported(PasskeyPrfUnsupportedException ex) {
        return problem(HttpStatus.UNPROCESSABLE_ENTITY, AuthProblems.PASSKEY_PRF_UNSUPPORTED);
    }

    @ExceptionHandler(UnknownCredentialException.class)
    public ResponseEntity<ProblemDetail> handleUnknownCredential(UnknownCredentialException ex) {
        return problem(HttpStatus.UNAUTHORIZED, AuthProblems.UNKNOWN_CREDENTIAL);
    }

    @ExceptionHandler(AuthenticationFailedException.class)
    public ResponseEntity<ProblemDetail> handleAuthenticationFailed(AuthenticationFailedException ex) {
        return problem(HttpStatus.UNAUTHORIZED, AuthProblems.AUTHENTICATION_FAILED);
    }

    @ExceptionHandler(InvalidSessionException.class)
    public ResponseEntity<ProblemDetail> handleInvalidSession(InvalidSessionException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .header(HttpHeaders.SET_COOKIE, refreshCookies.clear().toString())
                .body(AuthProblems.of(HttpStatus.UNAUTHORIZED, AuthProblems.INVALID_SESSION));
    }

    @ExceptionHandler(MissingWalletRequestHeaderException.class)
    public ResponseEntity<ProblemDetail> handleMissingWalletRequestHeader(MissingWalletRequestHeaderException ex) {
        return problem(HttpStatus.FORBIDDEN, AuthProblems.FORBIDDEN);
    }

    /** AD-5: no Relying Party without {@code ebw.webauthn.rp_id}; never derived from the Host header. */
    @ExceptionHandler(TenantConfigMissingException.class)
    public ResponseEntity<ProblemDetail> handleTenantConfigMissing(TenantConfigMissingException ex) {
        log.error("Registration and access unavailable: {}", ex.getMessage());
        return problem(HttpStatus.INTERNAL_SERVER_ERROR, AuthProblems.SERVER_ERROR);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleUnexpected(Exception ex) {
        // Class only: database messages may carry personal data (for instance the email of a unique key).
        log.error("Unhandled exception in the registration and access API: {}", ex.getClass().getName());
        return problem(HttpStatus.INTERNAL_SERVER_ERROR, AuthProblems.SERVER_ERROR);
    }

    private static ResponseEntity<ProblemDetail> problem(HttpStatus status, String type) {
        return ResponseEntity.status(status)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(AuthProblems.of(status, type));
    }
}
