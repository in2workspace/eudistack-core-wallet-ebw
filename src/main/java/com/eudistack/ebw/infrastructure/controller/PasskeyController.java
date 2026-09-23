package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.*;
import com.eudistack.ebw.infrastructure.controller.dto.ConfirmSessionRequest;
import com.eudistack.ebw.infrastructure.controller.dto.PasskeyResponse;
import com.eudistack.ebw.infrastructure.controller.dto.RegisterPasskeyRequest;
import com.eudistack.ebw.infrastructure.controller.dto.UpdatePasskeyRequest;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth/passkeys")
@Validated
public class PasskeyController {

    // DEBUG EUD-BUG-refresh-token: temporary diagnostic logging, remove before commit.
    private static final Logger log = LoggerFactory.getLogger(PasskeyController.class);

    private final RegisterPasskeyWorkflow registerPasskeyWorkflow;
    private final ListPasskeysWorkflow listPasskeysWorkflow;
    private final UpdatePasskeyWorkflow updatePasskeyWorkflow;
    private final DeletePasskeyWorkflow deletePasskeyWorkflow;
    private final RevokePasskeySessionsWorkflow revokePasskeySessionsWorkflow;
    private final ConfirmPasskeySessionWorkflow confirmPasskeySessionWorkflow;

    public PasskeyController(RegisterPasskeyWorkflow registerPasskeyWorkflow,
                             ListPasskeysWorkflow listPasskeysWorkflow,
                             UpdatePasskeyWorkflow updatePasskeyWorkflow,
                             DeletePasskeyWorkflow deletePasskeyWorkflow,
                             RevokePasskeySessionsWorkflow revokePasskeySessionsWorkflow,
                             ConfirmPasskeySessionWorkflow confirmPasskeySessionWorkflow) {
        this.registerPasskeyWorkflow = registerPasskeyWorkflow;
        this.listPasskeysWorkflow = listPasskeysWorkflow;
        this.updatePasskeyWorkflow = updatePasskeyWorkflow;
        this.deletePasskeyWorkflow = deletePasskeyWorkflow;
        this.revokePasskeySessionsWorkflow = revokePasskeySessionsWorkflow;
        this.confirmPasskeySessionWorkflow = confirmPasskeySessionWorkflow;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<PasskeyResponse> register(@Valid @RequestBody RegisterPasskeyRequest request,
                                          JwtAuthenticationToken auth,
                                          ServerHttpRequest httpRequest) {
        log.info("DEBUG POST /passkeys: userId={} credentialId={} refreshToken={} ip={}",
                auth.getUserId(), request.credentialId(), request.refreshToken(), clientIp(httpRequest));
        return registerPasskeyWorkflow.registerPasskey(
                        auth.getUserId(), request.credentialId(), request.displayName(),
                        request.userAgent(), request.refreshToken())
                .map(PasskeyResponse::from);
    }

    @GetMapping
    public Mono<List<PasskeyResponse>> list(JwtAuthenticationToken auth) {
        return listPasskeysWorkflow.listPasskeys(auth.getUserId())
                .map(PasskeyResponse::from)
                .collectList();
    }

    @PatchMapping("/{id}")
    public Mono<PasskeyResponse> update(@PathVariable UUID id,
                                        @Valid @RequestBody UpdatePasskeyRequest request,
                                        JwtAuthenticationToken auth) {
        return updatePasskeyWorkflow.updatePasskey(auth.getUserId(), id, request.displayName())
                .map(PasskeyResponse::from);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> delete(@PathVariable UUID id, JwtAuthenticationToken auth) {
        return deletePasskeyWorkflow.deletePasskey(auth.getUserId(), id);
    }

    @PostMapping("/{id}/revoke-sessions")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> revokeSessions(@PathVariable UUID id, JwtAuthenticationToken auth) {
        return revokePasskeySessionsWorkflow.revokeSessions(auth.getUserId(), id);
    }

    @PostMapping("/{id}/confirm-session")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> confirmSession(@PathVariable UUID id,
                                     @Valid @RequestBody ConfirmSessionRequest request,
                                     JwtAuthenticationToken auth,
                                     ServerHttpRequest httpRequest) {
        log.info("DEBUG POST /passkeys/{}/confirm-session: userId={} refreshToken={} ip={} userAgent={}",
                id, auth.getUserId(), request.refreshToken(), clientIp(httpRequest), userAgent(httpRequest));
        return confirmPasskeySessionWorkflow.confirmSession(auth.getUserId(), id, request.refreshToken());
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
}
