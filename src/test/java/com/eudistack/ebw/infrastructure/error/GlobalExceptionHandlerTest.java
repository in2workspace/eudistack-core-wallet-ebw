package com.eudistack.ebw.infrastructure.error;

import com.eudistack.ebw.domain.model.exception.InvalidOtpException;
import com.eudistack.ebw.domain.model.exception.OtpExpiredException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import java.util.Map;

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
}
