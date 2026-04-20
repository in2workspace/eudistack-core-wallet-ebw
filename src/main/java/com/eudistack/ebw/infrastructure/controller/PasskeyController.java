package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.*;
import com.eudistack.ebw.infrastructure.controller.dto.PasskeyResponse;
import com.eudistack.ebw.infrastructure.controller.dto.RegisterPasskeyRequest;
import com.eudistack.ebw.infrastructure.controller.dto.UpdatePasskeyRequest;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth/passkeys")
@Validated
public class PasskeyController {

    private final RegisterPasskeyWorkflow registerPasskeyWorkflow;
    private final ListPasskeysWorkflow listPasskeysWorkflow;
    private final UpdatePasskeyWorkflow updatePasskeyWorkflow;
    private final DeletePasskeyWorkflow deletePasskeyWorkflow;
    private final RevokePasskeySessionsWorkflow revokePasskeySessionsWorkflow;

    public PasskeyController(RegisterPasskeyWorkflow registerPasskeyWorkflow,
                             ListPasskeysWorkflow listPasskeysWorkflow,
                             UpdatePasskeyWorkflow updatePasskeyWorkflow,
                             DeletePasskeyWorkflow deletePasskeyWorkflow,
                             RevokePasskeySessionsWorkflow revokePasskeySessionsWorkflow) {
        this.registerPasskeyWorkflow = registerPasskeyWorkflow;
        this.listPasskeysWorkflow = listPasskeysWorkflow;
        this.updatePasskeyWorkflow = updatePasskeyWorkflow;
        this.deletePasskeyWorkflow = deletePasskeyWorkflow;
        this.revokePasskeySessionsWorkflow = revokePasskeySessionsWorkflow;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<PasskeyResponse> register(@Valid @RequestBody RegisterPasskeyRequest request,
                                          JwtAuthenticationToken auth) {
        return registerPasskeyWorkflow.registerPasskey(
                        auth.getUserId(), request.credentialId(), request.displayName(),
                        request.userAgent())
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
}
