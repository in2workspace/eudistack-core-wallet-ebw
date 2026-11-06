package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.CreateOnboardingTicketWorkflow;
import com.eudistack.ebw.application.workflow.CreateOnboardingTicketWorkflow.CreateOnboardingTicketCommand;
import com.eudistack.ebw.domain.model.OnboardingTicketIssued;
import com.eudistack.ebw.domain.model.exception.OnboardingDisabledException;
import com.eudistack.ebw.infrastructure.controller.support.RefreshCookies;
import com.eudistack.ebw.infrastructure.security.SystemCaller;
import com.eudistack.ebw.infrastructure.security.SystemTokenWebFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;

import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link OnboardingTicketController}: status codes and problems of the contract. */
class OnboardingTicketControllerTest {

    private CreateOnboardingTicketWorkflow workflow;
    private WebTestClient client;

    @BeforeEach
    void setUp() {
        workflow = mock(CreateOnboardingTicketWorkflow.class);
        WebFilter authenticated = (exchange, chain) -> {
            exchange.getAttributes().put(SystemTokenWebFilter.SYSTEM_CALLER_ATTRIBUTE, new SystemCaller("portal"));
            return chain.filter(exchange);
        };
        client = WebTestClient.bindToController(new OnboardingTicketController(workflow))
                .controllerAdvice(new AuthProblemExceptionHandler(mock(RefreshCookies.class)))
                .webFilter(authenticated)
                .build();
    }

    private WebTestClient.ResponseSpec post(Map<String, Object> body) {
        return client.post().uri("/api/v1/onboarding-tickets").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body).exchange();
    }

    @Test
    void create_valid_answers201WithUrlAndLifetime() {
        // Arrange
        when(workflow.create(new CreateOnboardingTicketCommand("ana@example.com", null, null, "portal")))
                .thenReturn(Mono.just(new OnboardingTicketIssued("https://sandbox.example/t/abc", 300)));

        // Act + Assert
        post(Map.of("email", "ana@example.com"))
                .expectStatus().isCreated()
                .expectBody()
                .jsonPath("$.onboardingUrl").isEqualTo("https://sandbox.example/t/abc")
                .jsonPath("$.expiresIn").isEqualTo(300);
    }

    @Test
    void create_invalidBody_answers400InvalidRequest() {
        // Act + Assert
        post(Map.of("email", "not-an-email")).expectStatus().isBadRequest()
                .expectBody().jsonPath("$.type").isEqualTo("invalid_request");
        post(Map.of("email", "a".repeat(250) + "@x.es")).expectStatus().isBadRequest();
        post(Map.of("email", "ana@example.com", "expiresIn", 30)).expectStatus().isBadRequest();
        post(Map.of("email", "ana@example.com", "credentialOffer", "x".repeat(2049))).expectStatus().isBadRequest();
        verify(workflow, never()).create(any());
    }

    @Test
    void create_disabledTenant_answers403OnboardingDisabled() {
        // Arrange
        when(workflow.create(any())).thenReturn(Mono.error(new OnboardingDisabledException()));

        // Act + Assert
        post(Map.of("email", "ana@example.com"))
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.type").isEqualTo("onboarding_disabled");
    }
}
