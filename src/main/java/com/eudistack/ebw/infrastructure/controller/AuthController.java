package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.RegisterWorkflow;
import com.eudistack.ebw.application.workflow.VerifyEmailWorkflow;
import com.eudistack.ebw.infrastructure.controller.dto.RegisterRequest;
import com.eudistack.ebw.infrastructure.controller.dto.VerifyEmailRequest;
import com.eudistack.ebw.infrastructure.controller.dto.VerifyEmailResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/** Email verification: one-time code and registration ticket (EUD-8 contract). */
@RestController
@RequestMapping("/api/v1/auth")
@Validated
public class AuthController {

    private final RegisterWorkflow registerWorkflow;
    private final VerifyEmailWorkflow verifyEmailWorkflow;

    public AuthController(RegisterWorkflow registerWorkflow, VerifyEmailWorkflow verifyEmailWorkflow) {
        this.registerWorkflow = registerWorkflow;
        this.verifyEmailWorkflow = verifyEmailWorkflow;
    }

    /** Same response whether the email has an account or not. */
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public Mono<Void> register(@Valid @RequestBody RegisterRequest request) {
        return registerWorkflow.registerUser(request.email());
    }

    @PostMapping("/verify-email")
    public Mono<VerifyEmailResponse> verifyEmail(@Valid @RequestBody VerifyEmailRequest request) {
        return verifyEmailWorkflow.verifyEmail(request.email(), request.code())
                .map(VerifyEmailResponse::from);
    }
}
