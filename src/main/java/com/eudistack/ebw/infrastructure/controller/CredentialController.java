package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.DeleteCredentialWorkflow;
import com.eudistack.ebw.application.workflow.GetCredentialWorkflow;
import com.eudistack.ebw.application.workflow.ListCredentialsWorkflow;
import com.eudistack.ebw.application.workflow.StoreCredentialWorkflow;
import com.eudistack.ebw.application.workflow.UpdateCredentialStatusWorkflow;
import com.eudistack.ebw.infrastructure.controller.dto.CredentialDetailResponse;
import com.eudistack.ebw.infrastructure.controller.dto.StoreCredentialRequest;
import com.eudistack.ebw.infrastructure.controller.dto.UpdateStatusRequest;
import com.eudistack.ebw.infrastructure.controller.dto.VerifiableCredentialResponse;
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
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/credentials")
@Validated
public class CredentialController {

    private final StoreCredentialWorkflow storeCredentialWorkflow;
    private final ListCredentialsWorkflow listCredentialsWorkflow;
    private final GetCredentialWorkflow getCredentialWorkflow;
    private final UpdateCredentialStatusWorkflow updateCredentialStatusWorkflow;
    private final DeleteCredentialWorkflow deleteCredentialWorkflow;

    public CredentialController(StoreCredentialWorkflow storeCredentialWorkflow,
                                 ListCredentialsWorkflow listCredentialsWorkflow,
                                 GetCredentialWorkflow getCredentialWorkflow,
                                 UpdateCredentialStatusWorkflow updateCredentialStatusWorkflow,
                                 DeleteCredentialWorkflow deleteCredentialWorkflow) {
        this.storeCredentialWorkflow = storeCredentialWorkflow;
        this.listCredentialsWorkflow = listCredentialsWorkflow;
        this.getCredentialWorkflow = getCredentialWorkflow;
        this.updateCredentialStatusWorkflow = updateCredentialStatusWorkflow;
        this.deleteCredentialWorkflow = deleteCredentialWorkflow;
    }

    @PostMapping
    public Mono<ResponseEntity<CredentialDetailResponse>> store(
            @Valid @RequestBody StoreCredentialRequest request,
            JwtAuthenticationToken auth) {
        return storeCredentialWorkflow.storeCredential(
                        auth.getUserId(), request.credentialRaw(), request.format(),
                        request.credentialConfigurationId(), request.kid(), request.issuerMetadata(), null)
                .map(credential -> ResponseEntity
                        .created(URI.create("/api/v1/credentials/" + credential.getId()))
                        .body(CredentialDetailResponse.from(credential)));
    }

    @GetMapping
    public Mono<List<VerifiableCredentialResponse>> list(
            @RequestParam(required = false) String status,
            @RequestParam(name = "credential_configuration_id", required = false) String credentialConfigId,
            @RequestParam(required = false) String issuer,
            JwtAuthenticationToken auth) {
        return listCredentialsWorkflow.listCredentials(auth.getUserId(), status, credentialConfigId, issuer)
                .collectList();
    }

    @GetMapping("/{id}")
    public Mono<VerifiableCredentialResponse> getById(@PathVariable UUID id, JwtAuthenticationToken auth) {
        return getCredentialWorkflow.getCredential(auth.getUserId(), id);
    }

    @PatchMapping("/{id}/status")
    public Mono<CredentialDetailResponse> updateStatus(@PathVariable UUID id,
                                                        @Valid @RequestBody UpdateStatusRequest request,
                                                        JwtAuthenticationToken auth) {
        return updateCredentialStatusWorkflow.updateStatus(auth.getUserId(), id, request.status())
                .map(CredentialDetailResponse::from);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> delete(@PathVariable UUID id, JwtAuthenticationToken auth) {
        return deleteCredentialWorkflow.deleteCredential(auth.getUserId(), id);
    }
}
