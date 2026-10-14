package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.domain.model.AuthRejectionReason;
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
import com.eudistack.ebw.infrastructure.controller.support.RefreshCookies;
import com.eudistack.ebw.infrastructure.controller.support.WalletRequestHeader.MissingWalletRequestHeaderException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ServerWebInputException;

import java.util.function.Function;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/** Unit tests for {@link AuthProblemExceptionHandler}: contract code in {@code type}, problem+json. */
class AuthProblemExceptionHandlerTest {

    private final AuthProblemExceptionHandler handler = new AuthProblemExceptionHandler(new RefreshCookies());

    static Stream<Arguments> problems() {
        return Stream.of(
                Arguments.of(call(h -> h.handleInvalidRequest(new ServerWebInputException("bad"))), 400, "invalid_request"),
                Arguments.of(call(h -> h.handleInvalidCode(new InvalidOtpException())), 401, "invalid_code"),
                Arguments.of(call(h -> h.handleExpiredCode(new OtpExpiredException())), 401, "expired_code"),
                Arguments.of(call(h -> h.handleTooManyAttempts(new TooManyAttemptsException())), 429, "too_many_attempts"),
                Arguments.of(call(h -> h.handleInvalidTicket(new InvalidTicketException())), 401, "invalid_ticket"),
                Arguments.of(call(h -> h.handleRegistrationFailed(
                        new RegistrationFailedException(AuthRejectionReason.VERIFICATION_FAILED))), 400, "registration_failed"),
                Arguments.of(call(h -> h.handlePrfUnsupported(new PasskeyPrfUnsupportedException())), 422,
                        "passkey_prf_unsupported"),
                Arguments.of(call(h -> h.handleUnknownCredential(new UnknownCredentialException())), 401,
                        "unknown_credential"),
                Arguments.of(call(h -> h.handleAuthenticationFailed(
                        new AuthenticationFailedException(AuthRejectionReason.SIGN_COUNT_NOT_ADVANCED))), 401,
                        "authentication_failed"),
                Arguments.of(call(h -> h.handleMissingWalletRequestHeader(new MissingWalletRequestHeaderException())),
                        403, "forbidden"),
                Arguments.of(call(h -> h.handleTenantConfigMissing(
                        new TenantConfigMissingException("t", "ebw.webauthn.rp_id"))), 500, "server_error"),
                Arguments.of(call(h -> h.handleUnexpected(new IllegalStateException("duplicate key a@b.c"))), 500,
                        "server_error"));
    }

    private static Function<AuthProblemExceptionHandler, ResponseEntity<ProblemDetail>> call(
            Function<AuthProblemExceptionHandler, ResponseEntity<ProblemDetail>> call) {
        return call;
    }

    @ParameterizedTest
    @MethodSource("problems")
    void handle_exception_returnsTheContractProblem(
            Function<AuthProblemExceptionHandler, ResponseEntity<ProblemDetail>> call, int status, String type) {
        // Act
        var response = call.apply(handler);

        // Assert
        assertThat(response.getStatusCode().value()).isEqualTo(status);
        assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_PROBLEM_JSON);
        assertThat(response.getBody().getType().toString()).isEqualTo(type);
        assertThat(response.getBody().getDetail()).isNull();
    }

    @Test
    void handleRateLimited_limitReached_returnsRetryAfter() {
        // Act
        var response = handler.handleRateLimited(new RateLimitExceededException(3600));

        // Assert
        assertThat(response.getStatusCode().value()).isEqualTo(429);
        assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("3600");
        assertThat(response.getBody().getType().toString()).isEqualTo("rate_limited");
    }

    @Test
    void handleInvalidSession_anySession_clearsTheRefreshCookie() {
        // Act
        var response = handler.handleInvalidSession(new InvalidSessionException());

        // Assert
        assertThat(response.getStatusCode().value()).isEqualTo(401);
        assertThat(response.getBody().getType().toString()).isEqualTo("invalid_session");
        assertThat(response.getHeaders().getFirst(HttpHeaders.SET_COOKIE))
                .startsWith("__Host-wallet_refresh=;").contains("Max-Age=0");
    }
}
