package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.RedeemOnboardingTicketWorkflow;
import com.eudistack.ebw.infrastructure.controller.dto.RedeemOnboardingTicketRequest;
import com.eudistack.ebw.infrastructure.controller.dto.RedeemOnboardingTicketResponse;
import com.eudistack.ebw.infrastructure.security.ActiveSessionChecker;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import jakarta.validation.Valid;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Optional;
import java.util.UUID;

/**
 * Onboarding ticket endpoints of the Wallet App (EUD-8 contract, design §2.6). Public routes: they
 * need no session ({@code PublicRoutes}).
 */
@RestController
@RequestMapping("/api/v1/auth/onboarding-tickets")
@Validated
public class OnboardingRedemptionController {

    private final RedeemOnboardingTicketWorkflow redeemWorkflow;
    private final ActiveSessionChecker activeSessionChecker;

    public OnboardingRedemptionController(RedeemOnboardingTicketWorkflow redeemWorkflow,
                                          ActiveSessionChecker activeSessionChecker) {
        this.redeemWorkflow = redeemWorkflow;
        this.activeSessionChecker = activeSessionChecker;
    }

    /**
     * The session token is optional. On a public route the JWT filter does not check that the
     * session is still alive, so it is checked here: a token of an ended session counts as none.
     */
    @PostMapping("/redeem")
    public Mono<RedeemOnboardingTicketResponse> redeem(@Valid @RequestBody RedeemOnboardingTicketRequest request) {
        return activeSessionUser()
                .map(Optional::of)
                .defaultIfEmpty(Optional.empty())
                .flatMap(sessionUser -> redeemWorkflow.redeem(request.ticket(), sessionUser.orElse(null)))
                .map(RedeemOnboardingTicketResponse::from);
    }

    private Mono<UUID> activeSessionUser() {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(JwtAuthenticationToken.class::isInstance)
                .cast(JwtAuthenticationToken.class)
                .filterWhen(auth -> activeSessionChecker.isActive(auth.getSessionId()))
                .map(JwtAuthenticationToken::getUserId);
    }
}
