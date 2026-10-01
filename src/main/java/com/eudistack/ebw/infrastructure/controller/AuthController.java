package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.LogoutWorkflow;
import com.eudistack.ebw.application.workflow.RefreshTokenWorkflow;
import com.eudistack.ebw.application.workflow.RegisterWorkflow;
import com.eudistack.ebw.application.workflow.VerifyEmailWorkflow;
import com.eudistack.ebw.infrastructure.controller.dto.*;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/v1/auth")
@Validated
public class AuthController {

    private final RegisterWorkflow registerWorkflow;
    private final VerifyEmailWorkflow verifyEmailWorkflow;
    private final RefreshTokenWorkflow refreshTokenWorkflow;
    private final LogoutWorkflow logoutWorkflow;

    public AuthController(RegisterWorkflow registerWorkflow,
                          VerifyEmailWorkflow verifyEmailWorkflow,
                          RefreshTokenWorkflow refreshTokenWorkflow,
                          LogoutWorkflow logoutWorkflow) {
        this.registerWorkflow = registerWorkflow;
        this.verifyEmailWorkflow = verifyEmailWorkflow;
        this.refreshTokenWorkflow = refreshTokenWorkflow;
        this.logoutWorkflow = logoutWorkflow;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.OK)
    public Mono<MessageResponse> register(@Valid @RequestBody RegisterRequest request) {
        return registerWorkflow.registerUser(request.email(), request.mode())
                .thenReturn(new MessageResponse("If the email is valid, you will receive a verification code."));
    }

    @PostMapping("/verify-email")
    public Mono<AuthTokenResponse> verifyEmail(@Valid @RequestBody VerifyEmailRequest request) {
        return verifyEmailWorkflow.verifyEmail(request.email(), request.code())
                .map(AuthTokenResponse::from);
    }

    @PostMapping("/refresh")
    public Mono<AuthTokenResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        return refreshTokenWorkflow.refreshToken(request.refreshToken())
                .map(AuthTokenResponse::from);
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> logout(@Valid @RequestBody LogoutRequest request) {
        return logoutWorkflow.logout(request.refreshToken());
    }

    /**
     * No-op liveness check for the caller's own session. Reaching this method at all
     * means {@code JwtAuthenticationWebFilter} already accepted the access token —
     * including the session-revocation check — so there is nothing left to do here.
     * Not in the {@code permitAll} list on purpose: the wallet polls this endpoint in
     * the background so a revoked session (closed remotely, passkey deleted, device
     * removed) is caught — and the holder redirected to login — even on an otherwise
     * idle tab that isn't making any other request for the 401 to surface on.
     */
    @GetMapping("/session")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void checkSession() {
    }
}
