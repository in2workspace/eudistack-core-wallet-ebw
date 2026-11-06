package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.RedeemOnboardingTicketWorkflow;
import com.eudistack.ebw.domain.model.OnboardingTicketRedemption;
import com.eudistack.ebw.domain.model.exception.InvalidTicketException;
import com.eudistack.ebw.infrastructure.security.ActiveSessionChecker;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import com.eudistack.ebw.infrastructure.controller.support.RefreshCookies;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link OnboardingRedemptionController}: contract of the redemption (AC-06, AC-09, ES-02). */
class OnboardingRedemptionControllerTest {

    private static final String TICKET = "Zk3q9Xw2Lp7Rt4Vb8Nc1Ha";
    private static final String OFFER = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fi.example%2Fo";

    private RedeemOnboardingTicketWorkflow workflow;
    private ActiveSessionChecker activeSessionChecker;

    @BeforeEach
    void setUp() {
        workflow = mock(RedeemOnboardingTicketWorkflow.class);
        activeSessionChecker = mock(ActiveSessionChecker.class);
    }

    private WebTestClient client(JwtAuthenticationToken session) {
        var builder = WebTestClient.bindToController(new OnboardingRedemptionController(workflow,
                        activeSessionChecker))
                .controllerAdvice(new AuthProblemExceptionHandler(mock(RefreshCookies.class)));
        if (session != null) {
            WebFilter authenticated = (exchange, chain) -> chain.filter(exchange)
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(session));
            builder = builder.webFilter(authenticated);
        }
        return builder.build();
    }

    private static WebTestClient.ResponseSpec redeem(WebTestClient client, Object ticket) {
        return client.post().uri("/api/v1/auth/onboarding-tickets/redeem").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("ticket", ticket)).exchange();
    }

    private static JwtAuthenticationToken session(UUID userId, UUID sessionId) {
        return new JwtAuthenticationToken(userId, "ana@example.com", sessionId, UUID.randomUUID(), List.of());
    }

    @Test
    void redeem_withoutAccount_answersTheRegistrationTicketAndTheOffer() {
        // Arrange
        when(workflow.redeem(TICKET, null))
                .thenReturn(Mono.just(new OnboardingTicketRedemption(false, false, "rt_raw", 300L, OFFER)));

        // Act + Assert
        redeem(client(null), TICKET).expectStatus().isOk().expectBody()
                .jsonPath("$.hasPasskeys").isEqualTo(false)
                .jsonPath("$.sessionOfAccount").isEqualTo(false)
                .jsonPath("$.registrationTicket").isEqualTo("rt_raw")
                .jsonPath("$.expiresIn").isEqualTo(300)
                .jsonPath("$.credentialOffer").isEqualTo(OFFER);
    }

    @Test
    void redeem_withPasskeys_leavesOutTheRegistrationTicket() {
        // Arrange
        when(workflow.redeem(TICKET, null))
                .thenReturn(Mono.just(new OnboardingTicketRedemption(true, false, null, null, OFFER)));

        // Act + Assert
        redeem(client(null), TICKET).expectStatus().isOk().expectBody()
                .jsonPath("$.hasPasskeys").isEqualTo(true)
                .jsonPath("$.registrationTicket").doesNotExist()
                .jsonPath("$.expiresIn").doesNotExist();
    }

    @Test
    void redeem_withAnActiveSession_passesItsAccount() {
        // Arrange: AC-09
        var userId = UUID.randomUUID();
        var sessionId = UUID.randomUUID();
        when(activeSessionChecker.isActive(sessionId)).thenReturn(Mono.just(true));
        when(workflow.redeem(TICKET, userId))
                .thenReturn(Mono.just(new OnboardingTicketRedemption(true, true, null, null, OFFER)));

        // Act + Assert
        redeem(client(session(userId, sessionId)), TICKET).expectStatus().isOk().expectBody()
                .jsonPath("$.sessionOfAccount").isEqualTo(true);
    }

    @Test
    void redeem_withAnEndedSession_redeemsAsWithoutSession() {
        // Arrange: on a public route the JWT filter does not check the session
        var sessionId = UUID.randomUUID();
        when(activeSessionChecker.isActive(sessionId)).thenReturn(Mono.just(false));
        when(workflow.redeem(eq(TICKET), isNull()))
                .thenReturn(Mono.just(new OnboardingTicketRedemption(false, false, "rt_raw", 300L, null)));

        // Act + Assert
        redeem(client(session(UUID.randomUUID(), sessionId)), TICKET).expectStatus().isOk();
        verify(workflow).redeem(eq(TICKET), isNull());
    }

    @Test
    void redeem_invalidTicket_answers401InvalidTicket() {
        // Arrange: AC-06
        when(workflow.redeem(eq(TICKET), any())).thenReturn(Mono.error(new InvalidTicketException()));

        // Act + Assert
        redeem(client(null), TICKET).expectStatus().isUnauthorized().expectBody()
                .jsonPath("$.type").isEqualTo("invalid_ticket");
    }

    @Test
    void redeem_malformedTicket_answers400InvalidRequest() {
        // Act + Assert: ES-02
        redeem(client(null), "too-short").expectStatus().isBadRequest().expectBody()
                .jsonPath("$.type").isEqualTo("invalid_request");
        redeem(client(null), "Zk3q9Xw2Lp7Rt4Vb8Nc1H=").expectStatus().isBadRequest();
        verify(workflow, never()).redeem(anyString(), any());
    }
}
