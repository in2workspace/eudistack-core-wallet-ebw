package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.EndSessionWorkflow;
import com.eudistack.ebw.application.workflow.PasskeyAuthenticationWorkflow;
import com.eudistack.ebw.application.workflow.PasskeyAuthenticationWorkflow.OpenSessionCommand;
import com.eudistack.ebw.application.workflow.RefreshTokenWorkflow;
import com.eudistack.ebw.infrastructure.controller.dto.AuthenticationOptionsResponse;
import com.eudistack.ebw.infrastructure.controller.dto.OpenSessionRequest;
import com.eudistack.ebw.infrastructure.controller.dto.SessionResponse;
import com.eudistack.ebw.infrastructure.controller.support.BearerTickets;
import com.eudistack.ebw.infrastructure.controller.support.RefreshCookies;
import com.eudistack.ebw.infrastructure.controller.support.WalletRequestHeader;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/** Sign-in with a passkey and session lifecycle (EUD-8 contract). */
@RestController
@RequestMapping("/api/v1/auth")
@Validated
public class SessionController {

    private final PasskeyAuthenticationWorkflow authenticationWorkflow;
    private final RefreshTokenWorkflow refreshTokenWorkflow;
    private final EndSessionWorkflow endSessionWorkflow;
    private final RefreshCookies refreshCookies;
    private final ObjectMapper objectMapper;

    public SessionController(PasskeyAuthenticationWorkflow authenticationWorkflow,
                             RefreshTokenWorkflow refreshTokenWorkflow, EndSessionWorkflow endSessionWorkflow,
                             RefreshCookies refreshCookies, ObjectMapper objectMapper) {
        this.authenticationWorkflow = authenticationWorkflow;
        this.refreshTokenWorkflow = refreshTokenWorkflow;
        this.endSessionWorkflow = endSessionWorkflow;
        this.refreshCookies = refreshCookies;
        this.objectMapper = objectMapper;
    }

    @PostMapping("/sessions/options")
    public Mono<AuthenticationOptionsResponse> options(ServerHttpRequest request) {
        return authenticationWorkflow.startAuthentication(BearerTickets.read(request))
                .map(AuthenticationOptionsResponse::from);
    }

    @PostMapping("/sessions")
    public Mono<ResponseEntity<SessionResponse>> openSession(@Valid @RequestBody OpenSessionRequest body,
                                                             ServerHttpRequest request) {
        return Mono.fromCallable(() -> objectMapper.writeValueAsString(body.credential()))
                .map(credentialJson -> new OpenSessionCommand(BearerTickets.read(request), body.ceremonyId(),
                        credentialJson, refreshCookies.read(request)))
                .flatMap(authenticationWorkflow::openSession)
                .map(session -> ResponseEntity.status(HttpStatus.CREATED)
                        .header(HttpHeaders.SET_COOKIE,
                                refreshCookies.issue(session.refreshToken(), session.sessionExpiresAt()).toString())
                        .body(SessionResponse.from(session)));
    }

    @PostMapping("/refresh")
    public Mono<ResponseEntity<SessionResponse>> refresh(ServerHttpRequest request) {
        WalletRequestHeader.require(request);
        return refreshTokenWorkflow.refresh(refreshCookies.read(request))
                .map(session -> ResponseEntity.ok()
                        .header(HttpHeaders.SET_COOKIE,
                                refreshCookies.issue(session.refreshToken(), session.sessionExpiresAt()).toString())
                        .body(SessionResponse.from(session)));
    }

    @DeleteMapping("/sessions/current")
    public Mono<ResponseEntity<Void>> endCurrentSession(ServerHttpRequest request, JwtAuthenticationToken auth) {
        WalletRequestHeader.require(request);
        return endSessionWorkflow.endCurrentSession(auth.getUserId(), auth.getSessionId())
                .thenReturn(ResponseEntity.noContent()
                        .header(HttpHeaders.SET_COOKIE, refreshCookies.clear().toString())
                        .<Void>build());
    }

    @DeleteMapping("/sessions/others")
    public Mono<ResponseEntity<Void>> endOtherSessions(ServerHttpRequest request, JwtAuthenticationToken auth) {
        WalletRequestHeader.require(request);
        return endSessionWorkflow.endOtherSessions(auth.getUserId(), auth.getSessionId())
                .thenReturn(ResponseEntity.noContent().<Void>build());
    }
}
