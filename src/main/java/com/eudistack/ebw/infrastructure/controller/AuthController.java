package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.LogoutWorkflow;
import com.eudistack.ebw.application.workflow.RefreshTokenWorkflow;
import com.eudistack.ebw.application.workflow.RegisterWorkflow;
import com.eudistack.ebw.application.workflow.VerifyEmailWorkflow;
import com.eudistack.ebw.infrastructure.controller.dto.*;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/v1/auth")
@Validated
public class AuthController {

    // DEBUG EUD-BUG-refresh-token: temporary diagnostic logging, remove before commit.
    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

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
    public Mono<AuthTokenResponse> verifyEmail(@Valid @RequestBody VerifyEmailRequest request,
                                               ServerHttpRequest httpRequest) {
        log.info("DEBUG POST /verify-email: email={} ip={} userAgent={}",
                request.email(), clientIp(httpRequest), userAgent(httpRequest));
        return verifyEmailWorkflow.verifyEmail(request.email(), request.code())
                .map(AuthTokenResponse::from)
                .doOnNext(resp -> log.info("DEBUG POST /verify-email: ISSUED refreshToken={} ip={}",
                        resp.refreshToken(), clientIp(httpRequest)));
    }

    @PostMapping("/refresh")
    public Mono<AuthTokenResponse> refresh(@Valid @RequestBody RefreshRequest request,
                                           ServerHttpRequest httpRequest) {
        log.info("DEBUG POST /refresh: rawToken={} ip={} userAgent={}",
                request.refreshToken(), clientIp(httpRequest), userAgent(httpRequest));
        return refreshTokenWorkflow.refreshToken(request.refreshToken())
                .map(AuthTokenResponse::from)
                .doOnNext(resp -> log.info("DEBUG POST /refresh: SUCCESS newRefreshToken={} ip={}",
                        resp.refreshToken(), clientIp(httpRequest)))
                .doOnError(err -> log.warn("DEBUG POST /refresh: FAILED rawToken={} ip={} error={}",
                        request.refreshToken(), clientIp(httpRequest), err.toString()));
    }

    // DEBUG EUD-BUG-refresh-token: temporary diagnostic helpers, remove before commit.
    private static String clientIp(ServerHttpRequest request) {
        var forwardedFor = request.getHeaders().getFirst("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor;
        }
        return request.getRemoteAddress() != null ? request.getRemoteAddress().toString() : "unknown";
    }

    private static String userAgent(ServerHttpRequest request) {
        var ua = request.getHeaders().getFirst("User-Agent");
        return ua != null ? ua : "unknown";
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> logout(@Valid @RequestBody LogoutRequest request) {
        return logoutWorkflow.logout(request.refreshToken());
    }


}
