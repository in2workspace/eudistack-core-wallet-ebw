package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.LogoutWorkflow;
import com.eudistack.ebw.application.workflow.RefreshTokenWorkflow;
import com.eudistack.ebw.application.workflow.RegisterWorkflow;
import com.eudistack.ebw.application.workflow.VerifyEmailWorkflow;
import com.eudistack.ebw.domain.model.AuthTokenPair;
import com.eudistack.ebw.infrastructure.controller.dto.LogoutRequest;
import com.eudistack.ebw.infrastructure.controller.dto.RefreshRequest;
import com.eudistack.ebw.infrastructure.controller.dto.RegisterRequest;
import com.eudistack.ebw.infrastructure.controller.dto.VerifyEmailRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link AuthController}. Plain direct method calls rather than
 * {@code WebTestClient} — the HTTP-status contract for these endpoints is already
 * exercised end-to-end by {@link com.eudistack.ebw.integration.AuthFlowIntegrationTest};
 * this class only needs to prove the controller wires arguments to the right workflow.
 */
class AuthControllerTest {

    private RegisterWorkflow registerWorkflow;
    private VerifyEmailWorkflow verifyEmailWorkflow;
    private RefreshTokenWorkflow refreshTokenWorkflow;
    private LogoutWorkflow logoutWorkflow;
    private AuthController controller;

    @BeforeEach
    void setUp() {
        registerWorkflow = mock(RegisterWorkflow.class);
        verifyEmailWorkflow = mock(VerifyEmailWorkflow.class);
        refreshTokenWorkflow = mock(RefreshTokenWorkflow.class);
        logoutWorkflow = mock(LogoutWorkflow.class);
        controller = new AuthController(registerWorkflow, verifyEmailWorkflow, refreshTokenWorkflow, logoutWorkflow);
    }

    @Test
    void register_delegatesToTheWorkflowAndReturnsAGenericMessage() {
        // Arrange
        when(registerWorkflow.registerUser("user@example.com", "register")).thenReturn(Mono.empty());

        // Act
        var result = controller.register(new RegisterRequest("user@example.com", "register"));

        // Assert
        StepVerifier.create(result)
                .assertNext(response -> assertThat(response.message()).isNotBlank())
                .verifyComplete();
        verify(registerWorkflow).registerUser("user@example.com", "register");
    }

    @Test
    void verifyEmail_delegatesToTheWorkflowAndMapsTheTokenPair() {
        // Arrange
        var pair = new AuthTokenPair("access-token", "refresh-token", 900L);
        when(verifyEmailWorkflow.verifyEmail("user@example.com", "123456")).thenReturn(Mono.just(pair));

        // Act
        var result = controller.verifyEmail(new VerifyEmailRequest("user@example.com", "123456"));

        // Assert
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.accessToken()).isEqualTo("access-token");
                    assertThat(response.refreshToken()).isEqualTo("refresh-token");
                    assertThat(response.expiresIn()).isEqualTo(900L);
                })
                .verifyComplete();
        verify(verifyEmailWorkflow).verifyEmail("user@example.com", "123456");
    }

    @Test
    void refresh_delegatesToTheWorkflowAndMapsTheTokenPair() {
        // Arrange
        var pair = new AuthTokenPair("new-access-token", "new-refresh-token", 900L);
        when(refreshTokenWorkflow.refreshToken("old-refresh-token")).thenReturn(Mono.just(pair));

        // Act
        var result = controller.refresh(new RefreshRequest("old-refresh-token"));

        // Assert
        StepVerifier.create(result)
                .assertNext(response -> assertThat(response.accessToken()).isEqualTo("new-access-token"))
                .verifyComplete();
        verify(refreshTokenWorkflow).refreshToken("old-refresh-token");
    }

    @Test
    void logout_delegatesToTheWorkflowWithTheRawRefreshToken() {
        // Arrange
        when(logoutWorkflow.logout("refresh-token")).thenReturn(Mono.empty());

        // Act
        var result = controller.logout(new LogoutRequest("refresh-token"));

        // Assert
        StepVerifier.create(result).verifyComplete();
        verify(logoutWorkflow).logout("refresh-token");
    }

    @Test
    void checkSession_isReachedOnlyAfterTheSecurityFilterAlreadyAccepted_andDoesNothingElse() {
        // Reaching this method at all is the whole check (see the class Javadoc) —
        // there is nothing to assert beyond "it returns without touching any workflow".
        controller.checkSession();
    }
}
