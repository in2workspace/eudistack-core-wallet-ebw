package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.domain.model.exception.InvalidSessionException;
import com.eudistack.ebw.domain.model.exception.InvalidWalletInstanceException;
import com.eudistack.ebw.domain.model.exception.RateLimitExceededException;
import com.eudistack.ebw.domain.model.exception.WalletInstanceNotFoundException;
import com.eudistack.ebw.domain.model.exception.WalletInstanceRevokedException;
import com.eudistack.ebw.infrastructure.controller.support.AuthProblems;
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
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebInputException;

/**
 * Errors of the Wallet Instances API as RFC 9457 {@code application/problem+json}, with the contract code in
 * {@code type} (EUD-15 {@code annex/openapi.yaml}). Scoped to {@link WalletInstanceController}.
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice(assignableTypes = WalletInstanceController.class)
public class WalletInstanceProblemExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(WalletInstanceProblemExceptionHandler.class);

    /** Missing or malformed body, or a field that fails its constraints (including a non-UUID path id). */
    @ExceptionHandler({ServerWebInputException.class, InvalidWalletInstanceException.class})
    public ResponseEntity<ProblemDetail> handleInvalidRequest(Exception ex) {
        return problem(HttpStatus.BAD_REQUEST, AuthProblems.INVALID_REQUEST);
    }

    @ExceptionHandler(WalletInstanceNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleNotFound(WalletInstanceNotFoundException ex) {
        return problem(HttpStatus.NOT_FOUND, AuthProblems.INSTANCE_NOT_FOUND);
    }

    @ExceptionHandler(WalletInstanceRevokedException.class)
    public ResponseEntity<ProblemDetail> handleRevoked(WalletInstanceRevokedException ex) {
        return problem(HttpStatus.GONE, AuthProblems.INSTANCE_REVOKED);
    }

    @ExceptionHandler(RateLimitExceededException.class)
    public ResponseEntity<ProblemDetail> handleTooManyRequests(RateLimitExceededException ex) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .header(HttpHeaders.RETRY_AFTER, String.valueOf(ex.getRetryAfterSeconds()))
                .body(AuthProblems.of(HttpStatus.TOO_MANY_REQUESTS, AuthProblems.TOO_MANY_REQUESTS));
    }

    /** The account of the session is gone (it was deleted while the session was open). */
    @ExceptionHandler(InvalidSessionException.class)
    public ResponseEntity<ProblemDetail> handleInvalidSession(InvalidSessionException ex) {
        return problem(HttpStatus.UNAUTHORIZED, AuthProblems.INVALID_SESSION);
    }

    /** Framework errors with their own status (415, 405, 406...) keep it instead of becoming a 500. */
    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<ProblemDetail> handleResponseStatus(ResponseStatusException ex) {
        return ResponseEntity.status(ex.getStatusCode())
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(ex.getBody());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleUnexpected(Exception ex) {
        // Class only: database messages may carry personal data.
        log.error("Unhandled exception in the wallet instances API: {}", ex.getClass().getName());
        return problem(HttpStatus.INTERNAL_SERVER_ERROR, AuthProblems.SERVER_ERROR);
    }

    private static ResponseEntity<ProblemDetail> problem(HttpStatus status, String type) {
        return ResponseEntity.status(status)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(AuthProblems.of(status, type));
    }
}
