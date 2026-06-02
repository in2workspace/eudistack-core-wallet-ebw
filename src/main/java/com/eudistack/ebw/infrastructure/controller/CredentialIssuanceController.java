package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.StoreCredentialWorkflow;
import com.eudistack.ebw.infrastructure.controller.dto.CredentialDetailResponse;
import com.eudistack.ebw.infrastructure.controller.dto.FinalizeIssuanceRequest;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/v1/openid-credential-offer")
public class CredentialIssuanceController {

    private final StoreCredentialWorkflow storeCredentialWorkflow;

    public CredentialIssuanceController(StoreCredentialWorkflow storeCredentialWorkflow) {
        this.storeCredentialWorkflow = storeCredentialWorkflow;
    }

    @PostMapping("/credential-response")
    public Mono<CredentialDetailResponse> finalizeIssuance(
            @Valid @RequestBody FinalizeIssuanceRequest request,
            JwtAuthenticationToken auth) {
        String credentialRaw = request.extractCredentialRaw();
        return storeCredentialWorkflow.storeCredential(
                        auth.getUserId(),
                        credentialRaw,
                        request.format(),
                        request.credentialConfigurationId(),
                        request.holderKid() != null ? request.holderKid() : "",
                        request.issuerMetadata() != null ? request.issuerMetadata() : java.util.Map.of(),
                        request.holderKeyId())
                .map(CredentialDetailResponse::from);
    }
}
