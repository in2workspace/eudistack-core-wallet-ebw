package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.RegisterWorkflow;
import com.eudistack.ebw.application.workflow.VerifyEmailWorkflow;
import com.eudistack.ebw.domain.model.RegistrationTicketIssued;
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

/** Unit tests for {@link AuthController}: wiring to the email verification workflows. */
class AuthControllerTest {

    private RegisterWorkflow registerWorkflow;
    private VerifyEmailWorkflow verifyEmailWorkflow;
    private AuthController controller;

    @BeforeEach
    void setUp() {
        registerWorkflow = mock(RegisterWorkflow.class);
        verifyEmailWorkflow = mock(VerifyEmailWorkflow.class);
        controller = new AuthController(registerWorkflow, verifyEmailWorkflow);
    }

    @Test
    void register_validEmail_delegatesAndCompletesWithoutBody() {
        // Arrange
        when(registerWorkflow.registerUser("a@b.com")).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(controller.register(new RegisterRequest("a@b.com"))).verifyComplete();
        verify(registerWorkflow).registerUser("a@b.com");
    }

    @Test
    void verifyEmail_validCode_returnsTicketAndNoSession() {
        // Arrange
        when(verifyEmailWorkflow.verifyEmail("a@b.com", "123456"))
                .thenReturn(Mono.just(new RegistrationTicketIssued("ticket", 300, true)));

        // Act + Assert
        StepVerifier.create(controller.verifyEmail(new VerifyEmailRequest("a@b.com", "123456")))
                .assertNext(response -> {
                    assertThat(response.registrationTicket()).isEqualTo("ticket");
                    assertThat(response.expiresIn()).isEqualTo(300);
                    assertThat(response.hasPasskeys()).isTrue();
                })
                .verifyComplete();
    }
}
