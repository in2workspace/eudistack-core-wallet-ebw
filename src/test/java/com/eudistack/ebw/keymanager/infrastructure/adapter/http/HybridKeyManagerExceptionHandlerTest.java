package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.keymanager.domain.exception.HolderIsolationViolationException;
import com.eudistack.ebw.keymanager.domain.exception.InvalidCommitException;
import com.eudistack.ebw.keymanager.domain.exception.InvalidSignatureSubmissionException;
import com.eudistack.ebw.keymanager.domain.exception.OnboardingStateException;
import com.eudistack.ebw.keymanager.domain.exception.PrfSaltNotFoundException;
import com.eudistack.ebw.keymanager.domain.exception.PrfUnsupportedException;
import com.eudistack.ebw.keymanager.domain.exception.SignatureInvalidException;
import com.eudistack.ebw.keymanager.domain.exception.TenantWalletProfileUnsupportedException;
import com.eudistack.ebw.keymanager.domain.exception.UnsupportedCredentialFormatException;
import com.eudistack.ebw.wallet.profile.domain.exception.TenantUnknownException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.web.bind.support.WebExchangeBindException;

import java.net.URI;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link HybridKeyManagerExceptionHandler} — status, problem type and machine-readable
 * {@code error} code returned to the hybrid onboarding / signing clients.
 */
class HybridKeyManagerExceptionHandlerTest {

    private static final String TYPE_BASE = "urn:eudistack:error:keymanager:hybrid:";

    private final HybridKeyManagerExceptionHandler handler = new HybridKeyManagerExceptionHandler();

    static Stream<Arguments> problems() {
        return Stream.of(
                Arguments.of(call(h -> h.handleUnsupportedFormat(new UnsupportedCredentialFormatException("x"))),
                        HttpStatus.BAD_REQUEST, "unsupported-format", "unsupported_format"),
                Arguments.of(call(h -> h.handleSignatureInvalid(new SignatureInvalidException())),
                        HttpStatus.BAD_REQUEST, "signature-invalid", "signature_invalid"),
                Arguments.of(call(h -> h.handleInvalidSignatureSubmission(new InvalidSignatureSubmissionException("x"))),
                        HttpStatus.BAD_REQUEST, "invalid-request", "invalid_request"),
                Arguments.of(call(h -> h.handleInvalidCommit(new InvalidCommitException("x"))),
                        HttpStatus.BAD_REQUEST, "invalid-request", "invalid_request"),
                Arguments.of(call(h -> h.handleOnboardingState(new OnboardingStateException("x"))),
                        HttpStatus.CONFLICT, "idempotency-replay", "idempotency_replay"),
                Arguments.of(call(h -> h.handlePrfSaltNotFound(new PrfSaltNotFoundException("cred-1"))),
                        HttpStatus.NOT_FOUND, "wrap-handle-not-found", "wrap_handle_not_found"),
                Arguments.of(call(h -> h.handleHolderIsolation(new HolderIsolationViolationException("cred-1"))),
                        HttpStatus.FORBIDDEN, "holder-isolation-violation", "holder_isolation_violation"));
    }

    @ParameterizedTest
    @MethodSource("problems")
    void problemHandlers_returnStatusTypeAndErrorCode(
            Function<HybridKeyManagerExceptionHandler, ResponseEntity<ProblemDetail>> handlerCall,
            HttpStatus expectedStatus, String expectedType, String expectedError) {
        // Act
        var response = handlerCall.apply(handler);

        // Assert
        assertThat(response.getStatusCode()).isEqualTo(expectedStatus);
        assertThat(response.getBody().getType()).isEqualTo(URI.create(TYPE_BASE + expectedType));
        assertThat(response.getBody().getProperties()).containsEntry("error", expectedError);
    }

    @Test
    void handleValidation_returns400WithoutFieldDetails() throws Exception {
        // Arrange
        var exception = new WebExchangeBindException(new MethodParameter(Object.class.getMethod("toString"), -1),
                new BeanPropertyBindingResult(new Object(), "request"));

        // Act
        var response = handler.handleValidation(exception);

        // Assert
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody().getType()).isEqualTo(URI.create(TYPE_BASE + "invalid-request"));
        assertThat(response.getBody().getProperties()).isNull();
    }

    @Test
    void handlePrfUnsupported_returns422Problem() {
        // Act
        var problem = handler.handlePrfUnsupported(new PrfUnsupportedException());

        // Assert
        assertThat(problem.getStatus()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY.value());
        assertThat(problem.getProperties()).containsEntry("error", "prf_unsupported");
    }

    @Test
    void handleForbidden_returns403WithoutBody() {
        // Act
        var unsupported = handler.handleForbidden(new TenantWalletProfileUnsupportedException("sandbox"));
        var unknown = handler.handleForbidden(
                new TenantUnknownException(TenantUnknownException.Reason.TENANT_ABSENT_FROM_CONTEXT));

        // Assert
        assertThat(unsupported.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(unknown.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(unknown.getBody()).isNull();
    }

    @Test
    void handleGeneral_returnsInternalProblem() {
        // Act
        var response = handler.handleGeneral(new IllegalStateException("boom"));

        // Assert
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody().getType()).isEqualTo(URI.create(TYPE_BASE + "internal"));
    }

    private static Function<HybridKeyManagerExceptionHandler, ResponseEntity<ProblemDetail>> call(
            Function<HybridKeyManagerExceptionHandler, ResponseEntity<ProblemDetail>> handlerCall) {
        return handlerCall;
    }
}
