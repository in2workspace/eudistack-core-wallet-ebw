package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.BindWalletInstanceWorkflow;
import com.eudistack.ebw.application.workflow.ListWalletInstancesWorkflow;
import com.eudistack.ebw.application.workflow.RegisterWalletInstanceWorkflow;
import com.eudistack.ebw.application.workflow.RegisterWalletInstanceWorkflow.RegisterCommand;
import com.eudistack.ebw.application.workflow.RenameWalletInstanceWorkflow;
import com.eudistack.ebw.application.workflow.RevokeWalletInstanceWorkflow;
import com.eudistack.ebw.application.workflow.WalletSession;
import com.eudistack.ebw.infrastructure.controller.dto.BindWalletInstanceRequest;
import com.eudistack.ebw.infrastructure.controller.dto.RegisterWalletInstanceRequest;
import com.eudistack.ebw.infrastructure.controller.dto.RenameWalletInstanceRequest;
import com.eudistack.ebw.infrastructure.controller.dto.WalletInstanceResponse;
import com.eudistack.ebw.infrastructure.security.ActiveSessionChecker;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.UUID;

/**
 * Wallet Instances of the account (EUD-15 {@code annex/openapi.yaml}): registration and binding of the session
 * after it is opened, and the list, rename and revocation of the "Dispositivos" screen. Every route needs the
 * session access token; none of them needs the session to be bound already ({@code InstanceExemptRoutes}).
 * After a change to the binding of a session, its cached state is forgotten here, so the next request sees it.
 */
@RestController
@RequestMapping("/api/v1/wallet-instances")
@Validated
public class WalletInstanceController {

    private final RegisterWalletInstanceWorkflow registerWorkflow;
    private final BindWalletInstanceWorkflow bindWorkflow;
    private final ListWalletInstancesWorkflow listWorkflow;
    private final RenameWalletInstanceWorkflow renameWorkflow;
    private final RevokeWalletInstanceWorkflow revokeWorkflow;
    private final ActiveSessionChecker activeSessionChecker;

    public WalletInstanceController(RegisterWalletInstanceWorkflow registerWorkflow,
                                    BindWalletInstanceWorkflow bindWorkflow,
                                    ListWalletInstancesWorkflow listWorkflow,
                                    RenameWalletInstanceWorkflow renameWorkflow,
                                    RevokeWalletInstanceWorkflow revokeWorkflow,
                                    ActiveSessionChecker activeSessionChecker) {
        this.registerWorkflow = registerWorkflow;
        this.bindWorkflow = bindWorkflow;
        this.listWorkflow = listWorkflow;
        this.renameWorkflow = renameWorkflow;
        this.revokeWorkflow = revokeWorkflow;
        this.activeSessionChecker = activeSessionChecker;
    }

    @GetMapping
    public Mono<List<WalletInstanceResponse>> list(JwtAuthenticationToken auth) {
        return listWorkflow.list(session(auth))
                .map(instances -> instances.stream()
                        .map(instance -> WalletInstanceResponse.from(instance, auth.getWalletInstanceId()))
                        .toList());
    }

    @PostMapping
    public Mono<ResponseEntity<WalletInstanceResponse>> register(
            @Valid @RequestBody RegisterWalletInstanceRequest body, JwtAuthenticationToken auth) {
        return registerWorkflow.register(session(auth), new RegisterCommand(body.displayName(), body.deviceType()))
                .flatMap(instance -> activeSessionChecker.forget(auth.getSessionId())
                        .thenReturn(ResponseEntity.status(HttpStatus.CREATED)
                                .body(WalletInstanceResponse.from(instance, instance.id()))));
    }

    @PutMapping("/current")
    public Mono<WalletInstanceResponse> bind(@Valid @RequestBody BindWalletInstanceRequest body,
                                             JwtAuthenticationToken auth) {
        return bindWorkflow.bind(session(auth), body.instanceId())
                .flatMap(instance -> activeSessionChecker.forget(auth.getSessionId())
                        .thenReturn(WalletInstanceResponse.from(instance, instance.id())));
    }

    @PatchMapping("/{id}")
    public Mono<WalletInstanceResponse> rename(@PathVariable UUID id,
                                               @Valid @RequestBody RenameWalletInstanceRequest body,
                                               JwtAuthenticationToken auth) {
        return renameWorkflow.rename(session(auth), id, body.displayName())
                .map(instance -> WalletInstanceResponse.from(instance, auth.getWalletInstanceId()));
    }

    @DeleteMapping("/{id}")
    public Mono<ResponseEntity<Void>> revoke(@PathVariable UUID id, JwtAuthenticationToken auth) {
        return revokeWorkflow.revoke(session(auth), id)
                .flatMapMany(Flux::fromIterable)
                .concatMap(activeSessionChecker::forget)
                .then(Mono.just(ResponseEntity.noContent().<Void>build()));
    }

    private static WalletSession session(JwtAuthenticationToken auth) {
        return new WalletSession(auth.getUserId(), auth.getSessionId(), auth.getPasskeyId(),
                auth.getWalletInstanceId());
    }
}
