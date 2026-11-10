package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.domain.model.exception.InvalidSessionException;
import com.eudistack.ebw.keymanager.domain.exception.PrfSaltNotFoundException;
import com.eudistack.ebw.keymanager.domain.exception.TenantWalletProfileUnsupportedException;
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
 * Maps the failures of {@link PasskeyPrfSaltController} to RFC 9457 problem details.
 *
 * <p>An attestation that does not exist, is not of the holder, belongs to another passkey or has no
 * public key yet is always the same 404, so a session cannot tell which case it is.</p>
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice(assignableTypes = PasskeyPrfSaltController.class)
public class PasskeyPrfKeyManagerExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(PasskeyPrfKeyManagerExceptionHandler.class);

    private static final String TYPE_BASE = "urn:eudistack:error:keymanager:passkey-prf:";
    private static final String UNSUPPORTED_CUSTODY_MODE_TYPE = "urn:eudistack:error:keymanager:unsupported-custody-mode";

    @ExceptionHandler(WebExchangeBindException.class)
    public ResponseEntity<ProblemDetail> handleValidation(WebExchangeBindException ex) {
        return problem(HttpStatus.BAD_REQUEST, "invalid-request");
    }

    @ExceptionHandler(InvalidSessionException.class)
    public ResponseEntity<ProblemDetail> handleInvalidSession(InvalidSessionException ex) {
        return problem(HttpStatus.UNAUTHORIZED, "invalid-session");
    }

    @ExceptionHandler(TenantWalletProfileUnsupportedException.class)
    public ResponseEntity<ProblemDetail> handleUnsupportedCustodyMode(TenantWalletProfileUnsupportedException ex) {
        // The same type as the key endpoints (KeyManagerExceptionHandler): one error, one type.
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.CONFLICT);
        problem.setType(URI.create(UNSUPPORTED_CUSTODY_MODE_TYPE));
        return ResponseEntity.status(HttpStatus.CONFLICT).body(problem);
    }

    @ExceptionHandler(TenantUnknownException.class)
    public ResponseEntity<Void> handleForbidden(TenantUnknownException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }

    @ExceptionHandler(PrfSaltNotFoundException.class)
    public ResponseEntity<ProblemDetail> handlePrfSaltNotFound(PrfSaltNotFoundException ex) {
        return problem(HttpStatus.NOT_FOUND, "not-found");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleGeneral(Exception ex) {
        log.error("keymanager.passkey-prf.unhandled exception_class={}", ex.getClass().getName());
        return problem(HttpStatus.INTERNAL_SERVER_ERROR, "internal");
    }

    private static ResponseEntity<ProblemDetail> problem(HttpStatus status, String type) {
        ProblemDetail problem = ProblemDetail.forStatus(status);
        problem.setType(URI.create(TYPE_BASE + type));
        return ResponseEntity.status(status).body(problem);
    }
}
