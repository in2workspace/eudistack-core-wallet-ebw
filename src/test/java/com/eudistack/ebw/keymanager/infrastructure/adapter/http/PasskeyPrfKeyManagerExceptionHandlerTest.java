package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.domain.model.exception.InvalidSessionException;
import com.eudistack.ebw.keymanager.domain.exception.PrfSaltNotFoundException;
import com.eudistack.ebw.keymanager.domain.exception.TenantWalletProfileUnsupportedException;
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

/** Status and problem type {@link PasskeyPrfKeyManagerExceptionHandler} returns to the Wallet App. */
class PasskeyPrfKeyManagerExceptionHandlerTest {

    private static final String TYPE_BASE = "urn:eudistack:error:keymanager:passkey-prf:";

    private final PasskeyPrfKeyManagerExceptionHandler handler = new PasskeyPrfKeyManagerExceptionHandler();

    static Stream<Arguments> problems() {
        return Stream.of(
                Arguments.of(call(h -> h.handleInvalidSession(new InvalidSessionException())),
                        HttpStatus.UNAUTHORIZED, "invalid-session"),
                Arguments.of(call(h -> h.handleUnsupportedCustodyMode(new TenantWalletProfileUnsupportedException("sandbox"))),
                        HttpStatus.CONFLICT, "unsupported-custody-mode"),
                Arguments.of(call(h -> h.handlePrfSaltNotFound(new PrfSaltNotFoundException("cred-1"))),
                        HttpStatus.NOT_FOUND, "not-found"),
                Arguments.of(call(h -> h.handleGeneral(new IllegalStateException("boom"))),
                        HttpStatus.INTERNAL_SERVER_ERROR, "internal")
        );
    }

    @ParameterizedTest
    @MethodSource("problems")
    void handler_exception_returnsProblemWithStatusAndType(
            Function<PasskeyPrfKeyManagerExceptionHandler, ResponseEntity<ProblemDetail>> handlerCall,
            HttpStatus status, String type) {
        // Arrange
        // handler and exception come from the parameters

        // Act
        var response = handlerCall.apply(handler);

        // Assert
        assertThat(response.getStatusCode()).isEqualTo(status);
        assertThat(response.getBody().getType()).isEqualTo(URI.create(TYPE_BASE + type));
    }

    @Test
    void handleValidation_invalidBody_returns400() throws NoSuchMethodException {
        // Arrange
        var parameter = new MethodParameter(String.class.getMethod("length"), -1);
        var exception = new WebExchangeBindException(parameter, new BeanPropertyBindingResult(new Object(), "request"));

        // Act
        var response = handler.handleValidation(exception);

        // Assert
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody().getType()).isEqualTo(URI.create(TYPE_BASE + "invalid-request"));
    }

    @Test
    void handleForbidden_unknownTenant_returns403WithoutBody() {
        // Arrange
        var exception = new TenantUnknownException(TenantUnknownException.Reason.PROFILE_NOT_SEEDED);

        // Act
        var response = handler.handleForbidden(exception);

        // Assert
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getBody()).isNull();
    }

    private static Function<PasskeyPrfKeyManagerExceptionHandler, ResponseEntity<ProblemDetail>> call(
            Function<PasskeyPrfKeyManagerExceptionHandler, ResponseEntity<ProblemDetail>> handlerCall) {
        return handlerCall;
    }
}
