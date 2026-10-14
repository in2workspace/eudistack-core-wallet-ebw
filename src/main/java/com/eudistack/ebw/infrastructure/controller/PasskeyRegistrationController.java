package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.PasskeyRegistrationWorkflow;
import com.eudistack.ebw.application.workflow.PasskeyRegistrationWorkflow.RegisterPasskeyCommand;
import com.eudistack.ebw.infrastructure.adapter.webauthn.WebAuthn4jVerifier;
import com.eudistack.ebw.infrastructure.controller.dto.RegisterPasskeyRequest;
import com.eudistack.ebw.infrastructure.controller.dto.RegistrationOptionsResponse;
import com.eudistack.ebw.infrastructure.controller.dto.SessionResponse;
import com.eudistack.ebw.infrastructure.controller.support.BearerTickets;
import com.eudistack.ebw.infrastructure.controller.support.RefreshCookies;
import com.eudistack.ebw.infrastructure.controller.support.WalletRequestHeader;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/** Registration ceremony of a passkey, with the registration ticket as bearer (EUD-8 contract). */
@RestController
@RequestMapping("/api/v1/auth/passkeys/registration")
@Validated
public class PasskeyRegistrationController {

    private static final int MAX_USER_AGENT_LENGTH = 512;

    private final PasskeyRegistrationWorkflow registrationWorkflow;
    private final RefreshCookies refreshCookies;
    private final ObjectMapper objectMapper;

    public PasskeyRegistrationController(PasskeyRegistrationWorkflow registrationWorkflow,
                                         RefreshCookies refreshCookies, ObjectMapper objectMapper) {
        this.registrationWorkflow = registrationWorkflow;
        this.refreshCookies = refreshCookies;
        this.objectMapper = objectMapper;
    }

    @PostMapping("/options")
    public Mono<RegistrationOptionsResponse> options(ServerHttpRequest request) {
        return registrationWorkflow.startRegistration(BearerTickets.read(request))
                .map(options -> RegistrationOptionsResponse.from(options, WebAuthn4jVerifier.SUPPORTED_ALGORITHMS));
    }

    @PostMapping
    public Mono<ResponseEntity<SessionResponse>> register(@Valid @RequestBody RegisterPasskeyRequest body,
                                                          ServerHttpRequest request) {
        WalletRequestHeader.require(request);
        return Mono.fromCallable(() -> objectMapper.writeValueAsString(body.credential()))
                .map(credentialJson -> new RegisterPasskeyCommand(BearerTickets.read(request), body.ceremonyId(),
                        credentialJson, body.prfSupported(), body.displayName(), userAgent(request),
                        refreshCookies.read(request)))
                .flatMap(registrationWorkflow::register)
                .map(session -> ResponseEntity.status(HttpStatus.CREATED)
                        .header(HttpHeaders.SET_COOKIE,
                                refreshCookies.issue(session.refreshToken(), session.sessionExpiresAt()).toString())
                        .body(SessionResponse.from(session)));
    }

    private static String userAgent(ServerHttpRequest request) {
        var userAgent = request.getHeaders().getFirst(HttpHeaders.USER_AGENT);
        if (userAgent == null) {
            return null;
        }
        return userAgent.length() > MAX_USER_AGENT_LENGTH ? userAgent.substring(0, MAX_USER_AGENT_LENGTH) : userAgent;
    }
}
