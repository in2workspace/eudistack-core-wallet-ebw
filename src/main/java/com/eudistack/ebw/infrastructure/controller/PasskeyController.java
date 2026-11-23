package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.ListPasskeysWorkflow;
import com.eudistack.ebw.infrastructure.controller.dto.PasskeyResponse;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * The passkeys of the account, read by the Wallet App only for the Signal API (EUD-8 FR-17). The API of
 * passkeys does not manage devices (EUD-15 AD-4): there are no routes to rename or delete a passkey nor to end
 * its sessions. Devices are the Wallet Instances ({@link WalletInstanceController}); registering a passkey is
 * {@link PasskeyRegistrationController}.
 */
@RestController
@RequestMapping("/api/v1/auth/passkeys")
public class PasskeyController {

    private final ListPasskeysWorkflow listPasskeysWorkflow;

    public PasskeyController(ListPasskeysWorkflow listPasskeysWorkflow) {
        this.listPasskeysWorkflow = listPasskeysWorkflow;
    }

    @GetMapping
    public Mono<List<PasskeyResponse>> list(JwtAuthenticationToken auth) {
        return listPasskeysWorkflow.listPasskeys(auth.getUserId())
                .map(PasskeyResponse::from)
                .collectList();
    }
}
