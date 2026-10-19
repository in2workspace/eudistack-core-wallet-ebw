package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.LogoutWorkflow;
import com.eudistack.ebw.application.workflow.RefreshTokenWorkflow;
import com.eudistack.ebw.application.workflow.RegisterWorkflow;
import com.eudistack.ebw.application.workflow.VerifyEmailWorkflow;
import com.eudistack.ebw.domain.model.AuthTokenPair;
import com.eudistack.ebw.domain.model.exception.InvalidTokenException;
import com.eudistack.ebw.infrastructure.controller.dto.AuthTokenResponse;
import com.eudistack.ebw.infrastructure.controller.dto.LogoutRequest;
import com.eudistack.ebw.infrastructure.controller.dto.RefreshRequest;
import com.eudistack.ebw.infrastructure.controller.dto.RegisterRequest;
import com.eudistack.ebw.infrastructure.controller.dto.VerifyEmailRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link AuthController} — direct method calls proving each endpoint delegates to its workflow
 * and maps the result. The HTTP contract (status codes, validation) is covered by
 * {@link com.eudistack.ebw.integration.AuthFlowIntegrationTest}.
 */
@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    private static final String EMAIL = "holder@example.com";

    @Mock private RegisterWorkflow registerWorkflow;
    @Mock private VerifyEmailWorkflow verifyEmailWorkflow;
    @Mock private RefreshTokenWorkflow refreshTokenWorkflow;
    @Mock private LogoutWorkflow logoutWorkflow;

    private AuthController controller;

    @BeforeEach
    void setUp() {
        controller = new AuthController(registerWorkflow, verifyEmailWorkflow, refreshTokenWorkflow, logoutWorkflow);
    }

    @Test
    void register_anyEmail_returnsTheSameNonEnumeratingMessage() {
        // Arrange
        when(registerWorkflow.registerUser(EMAIL, "login")).thenReturn(Mono.empty());

        // Act
        var result = controller.register(new RegisterRequest(EMAIL, "login"));

        // Assert
        StepVerifier.create(result)
                .assertNext(response -> assertThat(response.message())
                        .isEqualTo("If the email is valid, you will receive a verification code."))
                .verifyComplete();
        verify(registerWorkflow).registerUser(EMAIL, "login");
    }

    @Test
    void verifyEmail_validCode_returnsTheIssuedTokenPair() {
        // Arrange
        when(verifyEmailWorkflow.verifyEmail(EMAIL, "123456"))
                .thenReturn(Mono.just(new AuthTokenPair("access", "refresh", 900)));

        // Act
        var result = controller.verifyEmail(new VerifyEmailRequest(EMAIL, "123456"));

        // Assert
        StepVerifier.create(result)
                .expectNext(new AuthTokenResponse("access", "refresh", 900))
                .verifyComplete();
    }

    @Test
    void refresh_validToken_returnsTheRotatedPair() {
        // Arrange
        when(refreshTokenWorkflow.refreshToken("old-refresh"))
                .thenReturn(Mono.just(new AuthTokenPair("access-2", "refresh-2", 900)));

        // Act
        var result = controller.refresh(new RefreshRequest("old-refresh"));

        // Assert
        StepVerifier.create(result)
                .expectNext(new AuthTokenResponse("access-2", "refresh-2", 900))
                .verifyComplete();
    }

    @Test
    void refresh_invalidToken_propagatesTheWorkflowError() {
        // Arrange
        when(refreshTokenWorkflow.refreshToken("bad")).thenReturn(Mono.error(new InvalidTokenException()));

        // Act
        var result = controller.refresh(new RefreshRequest("bad"));

        // Assert
        StepVerifier.create(result).expectError(InvalidTokenException.class).verify();
    }

    @Test
    void logout_refreshToken_delegatesToTheLogoutWorkflow() {
        // Arrange
        when(logoutWorkflow.logout("refresh")).thenReturn(Mono.empty());

        // Act
        var result = controller.logout(new LogoutRequest("refresh"));

        // Assert
        StepVerifier.create(result).verifyComplete();
        verify(logoutWorkflow).logout("refresh");
    }
}
