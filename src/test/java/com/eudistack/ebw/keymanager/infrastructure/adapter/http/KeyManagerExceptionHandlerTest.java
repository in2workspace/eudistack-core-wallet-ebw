package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.keymanager.domain.exception.InvalidConsumerOriginException;
import com.eudistack.ebw.keymanager.domain.exception.InvalidKeyIdFormatException;
import com.eudistack.ebw.keymanager.domain.exception.KeyAccessDeniedException;
import com.eudistack.ebw.keymanager.domain.exception.SigningTypeFormatMismatchException;
import com.eudistack.ebw.keymanager.domain.exception.TenantWalletProfileUnsupportedException;
import com.eudistack.ebw.keymanager.domain.exception.UnsupportedCredentialFormatException;
import com.eudistack.ebw.keymanager.domain.exception.UnsupportedJwsAlgorithmException;
import com.eudistack.ebw.keymanager.domain.exception.UnsupportedSigningTypeException;
import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.SigningType;
import com.eudistack.ebw.wallet.profile.domain.exception.TenantUnknownException;
import io.r2dbc.spi.R2dbcNonTransientResourceException;
import io.r2dbc.spi.R2dbcTimeoutException;
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
import java.util.concurrent.TimeoutException;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link KeyManagerExceptionHandler} — status and problem type per exception, and the opaque
 * {@code KeyAccessDenied} body that hides the internal rejection reason (ADR-025).
 */
class KeyManagerExceptionHandlerTest {

    private static final String TYPE_BASE = "urn:eudistack:error:keymanager:";

    private final KeyManagerExceptionHandler handler = new KeyManagerExceptionHandler();

    static Stream<Arguments> problems() throws Exception {
        var bindException = new WebExchangeBindException(
                new MethodParameter(Object.class.getMethod("toString"), -1), bindingResultWithError());
        return Stream.of(
                Arguments.of(call(h -> h.handleValidation(bindException)), HttpStatus.BAD_REQUEST, "invalid-request"),
                Arguments.of(call(h -> h.handleInvalidKeyIdFormat(new InvalidKeyIdFormatException("x"))),
                        HttpStatus.BAD_REQUEST, "invalid-key-id"),
                Arguments.of(call(h -> h.handleInvalidConsumerOrigin(new InvalidConsumerOriginException("x"))),
                        HttpStatus.BAD_REQUEST, "invalid-consumer-origin"),
                Arguments.of(call(h -> h.handleUnsupportedFormat(new UnsupportedCredentialFormatException("x"))),
                        HttpStatus.BAD_REQUEST, "unsupported-format"),
                Arguments.of(call(h -> h.handleUnsupportedAlgorithm(
                                new UnsupportedJwsAlgorithmException(List.of("RS256"), List.of("ES256")))),
                        HttpStatus.UNPROCESSABLE_ENTITY, "unsupported-algorithm"),
                Arguments.of(call(h -> h.handleUnsupportedSigningType(
                                new UnsupportedSigningTypeException(SigningType.VP_ENVELOPE))),
                        HttpStatus.BAD_REQUEST, "unsupported-signing-type"),
                Arguments.of(call(h -> h.handleDbUnavailable(new R2dbcTimeoutException("slow"))),
                        HttpStatus.SERVICE_UNAVAILABLE, "service-unavailable"),
                Arguments.of(call(h -> h.handleDbUnavailable(new R2dbcNonTransientResourceException("down"))),
                        HttpStatus.SERVICE_UNAVAILABLE, "service-unavailable"),
                Arguments.of(call(h -> h.handleTimeout(new TimeoutException())), HttpStatus.GATEWAY_TIMEOUT,
                        "gateway-timeout"),
                Arguments.of(call(h -> h.handleGeneral(new IllegalStateException("boom"))),
                        HttpStatus.INTERNAL_SERVER_ERROR, "internal"));
    }

    @ParameterizedTest
    @MethodSource("problems")
    void problemHandlers_returnStatusAndTypedProblemWithoutDetail(
            Function<KeyManagerExceptionHandler, ResponseEntity<ProblemDetail>> handlerCall,
            HttpStatus expectedStatus, String expectedType) {
        // Act
        var response = handlerCall.apply(handler);

        // Assert
        assertThat(response.getStatusCode()).isEqualTo(expectedStatus);
        assertThat(response.getBody().getType()).isEqualTo(URI.create(TYPE_BASE + expectedType));
        assertThat(response.getBody().getDetail()).isNull();
    }

    @Test
    void handleKeyAccessDenied_anyInternalReason_returnsOpaque401() {
        // Act
        var response = handler.handleKeyAccessDenied(new KeyAccessDeniedException("KEY_REVOKED"));

        // Assert
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).isEqualTo(Map.of("error", "KeyAccessDenied"));
    }

    @Test
    void handleSigningTypeMismatch_returnsTheSameOpaque401() {
        // Act
        var response = handler.handleSigningTypeMismatch(
                new SigningTypeFormatMismatchException(SigningType.KB_JWT, CredentialFormat.VC_JWT));

        // Assert
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).isEqualTo(Map.of("error", "KeyAccessDenied"));
    }

    @Test
    void handleForbidden_unsupportedProfileOrUnknownTenant_returns403WithoutBody() {
        // Act
        var unsupported = handler.handleForbidden(new TenantWalletProfileUnsupportedException("sandbox"));
        var unknown = handler.handleForbidden(new TenantUnknownException(TenantUnknownException.Reason.PROFILE_NOT_SEEDED));

        // Assert
        assertThat(unsupported.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(unsupported.getBody()).isNull();
        assertThat(unknown.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    private static Function<KeyManagerExceptionHandler, ResponseEntity<ProblemDetail>> call(
            Function<KeyManagerExceptionHandler, ResponseEntity<ProblemDetail>> handlerCall) {
        return handlerCall;
    }

    private static BeanPropertyBindingResult bindingResultWithError() {
        var bindingResult = new BeanPropertyBindingResult(new Object(), "request");
        bindingResult.addError(new FieldError("request", "credential_id", "must not be blank"));
        return bindingResult;
    }
}
