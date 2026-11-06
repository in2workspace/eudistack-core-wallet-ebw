package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.CreateOnboardingTicketWorkflow;
import com.eudistack.ebw.application.workflow.CreateOnboardingTicketWorkflow.CreateOnboardingTicketCommand;
import com.eudistack.ebw.infrastructure.controller.dto.CreateOnboardingTicketRequest;
import com.eudistack.ebw.infrastructure.controller.dto.OnboardingTicketResponse;
import com.eudistack.ebw.infrastructure.security.SystemCaller;
import com.eudistack.ebw.infrastructure.security.SystemTokenWebFilter;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Onboarding ticket requested by an authorized system (EUD-8 contract, design §2.6). The system
 * token is checked by {@link SystemTokenWebFilter} before the request gets here.
 */
@RestController
@RequestMapping("/api/v1/onboarding-tickets")
@Validated
public class OnboardingTicketController {

    private final CreateOnboardingTicketWorkflow createWorkflow;

    public OnboardingTicketController(CreateOnboardingTicketWorkflow createWorkflow) {
        this.createWorkflow = createWorkflow;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<OnboardingTicketResponse> create(@Valid @RequestBody CreateOnboardingTicketRequest request,
                                                 ServerWebExchange exchange) {
        SystemCaller caller = exchange.getAttribute(SystemTokenWebFilter.SYSTEM_CALLER_ATTRIBUTE);
        if (caller == null) {
            // Only reachable if the filter did not run: never create a ticket without an authenticated system.
            return Mono.error(new IllegalStateException("No authenticated system on /onboarding-tickets"));
        }
        return createWorkflow.create(new CreateOnboardingTicketCommand(request.email(), request.credentialOffer(),
                        request.expiresIn(), caller.id()))
                .map(OnboardingTicketResponse::from);
    }
}
