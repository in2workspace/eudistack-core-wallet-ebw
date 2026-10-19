package com.eudistack.ebw.infrastructure.error;

import com.eudistack.ebw.domain.model.exception.CredentialNotFoundException;
import com.eudistack.ebw.domain.model.exception.DuplicatePasskeyException;
import com.eudistack.ebw.domain.model.exception.InvalidOtpException;
import com.eudistack.ebw.domain.model.exception.InvalidTokenException;
import com.eudistack.ebw.domain.model.exception.InvalidTransitionException;
import com.eudistack.ebw.domain.model.exception.LastPasskeyException;
import com.eudistack.ebw.domain.model.exception.MalformedCredentialException;
import com.eudistack.ebw.domain.model.exception.OtpExpiredException;
import com.eudistack.ebw.domain.model.exception.PasskeyNotFoundException;
import com.eudistack.ebw.domain.model.exception.PayloadTooLargeException;
import com.eudistack.ebw.domain.model.exception.RateLimitExceededException;
import com.eudistack.ebw.domain.model.exception.TokenFamilyCompromisedException;
import com.eudistack.ebw.domain.model.exception.TooManyAttemptsException;
import com.eudistack.ebw.domain.model.exception.UnsupportedFormatException;
import com.eudistack.ebw.domain.model.exception.UserAlreadyRegisteredException;
import com.eudistack.ebw.domain.model.exception.UserNotFoundException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.support.WebExchangeBindException;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for the OTP mappings of {@link GlobalExceptionHandler} (#1061173): an expired code
 * and a wrong code share the 401 status but carry distinct {@code error} values, so the wallet
 * can offer a resend only for the expired case.
 */
class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void handleInvalidOtp_returns401InvalidCode() {
        // Act
        var response = handler.handleInvalidOtp(new InvalidOtpException());

        // Assert
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).isEqualTo(Map.of(
                "error", "invalid_code",
                "message", "Invalid verification code"));
    }

    @Test
    void handleExpiredOtp_returns401ExpiredCode() {
        // Act
        var response = handler.handleExpiredOtp(new OtpExpiredException());

        // Assert
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).isEqualTo(Map.of(
                "error", "expired_code",
                "message", "Verification code has expired"));
    }

    // --- OAuth2-style auth errors ---

    static Stream<Arguments> authErrors() {
        return Stream.of(
                Arguments.of(handlerCall(h -> h.handleUserAlreadyRegistered(new UserAlreadyRegisteredException())),
                        HttpStatus.CONFLICT, "user_already_registered"),
                Arguments.of(handlerCall(h -> h.handleUserNotFound(new UserNotFoundException())),
                        HttpStatus.NOT_FOUND, "user_not_found"),
                Arguments.of(handlerCall(h -> h.handleTooManyAttempts(new TooManyAttemptsException())),
                        HttpStatus.TOO_MANY_REQUESTS, "too_many_attempts"),
                Arguments.of(handlerCall(h -> h.handleInvalidToken(new InvalidTokenException("JWT has expired"))),
                        HttpStatus.UNAUTHORIZED, "invalid_token"),
                Arguments.of(handlerCall(h -> h.handleTokenCompromised(new TokenFamilyCompromisedException())),
                        HttpStatus.UNAUTHORIZED, "token_compromised"));
    }

    @ParameterizedTest
    @MethodSource("authErrors")
    void authExceptionHandlers_returnOAuth2StyleErrorBody(
            Function<GlobalExceptionHandler, ResponseEntity<Map<String, String>>> call,
            HttpStatus expectedStatus, String expectedError) {
        // Act
        var response = call.apply(handler);

        // Assert
        assertThat(response.getStatusCode()).isEqualTo(expectedStatus);
        assertThat(response.getBody()).containsEntry("error", expectedError).containsKey("message");
    }

    // --- RFC 7807 problem details ---

    static Stream<Arguments> problemErrors() {
        return Stream.of(
                Arguments.of(problemCall(h -> h.handlePayloadTooLarge(new PayloadTooLargeException(1024))),
                        HttpStatus.PAYLOAD_TOO_LARGE, "payload-too-large"),
                Arguments.of(problemCall(h -> h.handlePasskeyNotFound(new PasskeyNotFoundException())),
                        HttpStatus.NOT_FOUND, "passkey-not-found"),
                Arguments.of(problemCall(h -> h.handleDuplicatePasskey(new DuplicatePasskeyException())),
                        HttpStatus.CONFLICT, "duplicate-passkey"),
                Arguments.of(problemCall(h -> h.handleLastPasskey(new LastPasskeyException())),
                        HttpStatus.CONFLICT, "last-passkey"),
                Arguments.of(problemCall(h -> h.handleInvalidTransition(new InvalidTransitionException("REVOKED", "VALID"))),
                        HttpStatus.UNPROCESSABLE_ENTITY, "invalid-transition"),
                Arguments.of(problemCall(h -> h.handleCredentialNotFound(new CredentialNotFoundException())),
                        HttpStatus.NOT_FOUND, "credential-not-found"),
                Arguments.of(problemCall(h -> h.handleUnsupportedFormat(new UnsupportedFormatException("mso_mdoc"))),
                        HttpStatus.BAD_REQUEST, "unsupported-format"),
                Arguments.of(problemCall(h -> h.handleMalformedCredential(new MalformedCredentialException("bad jwt"))),
                        HttpStatus.BAD_REQUEST, "malformed-credential"),
                Arguments.of(problemCall(h -> h.handleIllegalArgument(new IllegalArgumentException("Invalid status"))),
                        HttpStatus.BAD_REQUEST, "bad-request"));
    }

    @ParameterizedTest
    @MethodSource("problemErrors")
    void resourceExceptionHandlers_returnTypedProblemDetail(
            Function<GlobalExceptionHandler, ResponseEntity<ProblemDetail>> call,
            HttpStatus expectedStatus, String expectedTypeSuffix) {
        // Act
        var response = call.apply(handler);

        // Assert
        assertThat(response.getStatusCode()).isEqualTo(expectedStatus);
        assertThat(response.getBody().getStatus()).isEqualTo(expectedStatus.value());
        assertThat(response.getBody().getType()).isEqualTo(URI.create("urn:eudistack:error:" + expectedTypeSuffix));
    }

    @Test
    void handleRateLimit_returns429WithRetryAfterHeader() {
        // Act
        var response = handler.handleRateLimit(new RateLimitExceededException(3600));

        // Assert
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(response.getHeaders().getFirst("Retry-After")).isEqualTo("3600");
        assertThat(response.getBody().getType()).isEqualTo(URI.create("urn:eudistack:error:rate-limit-exceeded"));
    }

    @Test
    void handleValidation_fieldErrors_listsEachViolation() throws Exception {
        // Arrange
        var bindingResult = new BeanPropertyBindingResult(new Object(), "request");
        bindingResult.addError(new FieldError("request", "email", "must be a well-formed email address"));
        bindingResult.addError(new FieldError("request", "code", null, false, null, null, null));
        var exception = new WebExchangeBindException(
                new MethodParameter(Object.class.getMethod("toString"), -1), bindingResult);

        // Act
        var response = handler.handleValidation(exception);

        // Assert
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody().getDetail()).isEqualTo("Validation failed");
        assertThat(response.getBody().getProperties()).containsEntry("violations", List.of(
                Map.of("field", "email", "message", "must be a well-formed email address"),
                Map.of("field", "code", "message", "invalid")));
    }

    @Test
    void handleGeneral_unexpectedException_returnsGeneric500WithoutLeakingTheCause() {
        // Act
        var response = handler.handleGeneral(new IllegalStateException("db password=secret"));

        // Assert
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody().getDetail()).isEqualTo("An unexpected error occurred");
        assertThat(response.getBody().getType()).isEqualTo(URI.create("urn:eudistack:error:internal"));
    }

    private static Function<GlobalExceptionHandler, ResponseEntity<Map<String, String>>> handlerCall(
            Function<GlobalExceptionHandler, ResponseEntity<Map<String, String>>> call) {
        return call;
    }

    private static Function<GlobalExceptionHandler, ResponseEntity<ProblemDetail>> problemCall(
            Function<GlobalExceptionHandler, ResponseEntity<ProblemDetail>> call) {
        return call;
    }
}
