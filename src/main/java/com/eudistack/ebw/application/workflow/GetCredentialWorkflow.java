package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.exception.CredentialNotFoundException;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import com.eudistack.ebw.domain.service.CredentialService;
import com.eudistack.ebw.infrastructure.controller.dto.VerifiableCredentialResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.UUID;

@Service
public class GetCredentialWorkflow {

    private static final Logger log = LoggerFactory.getLogger(GetCredentialWorkflow.class);

    private final WalletCredentialRepository credentialRepository;
    private final CredentialService credentialService;

    public GetCredentialWorkflow(WalletCredentialRepository credentialRepository,
                                  CredentialService credentialService) {
        this.credentialRepository = credentialRepository;
        this.credentialService = credentialService;
    }

    public Mono<VerifiableCredentialResponse> getCredential(UUID userId, UUID credentialId) {
        return credentialRepository.findByIdAndUserId(credentialId, userId)
                .switchIfEmpty(Mono.error(new CredentialNotFoundException()))
                .flatMap(credential -> Mono
                        .fromCallable(() -> credentialService.toVerifiableCredential(credential))
                        .subscribeOn(Schedulers.boundedElastic()))
                .doOnSuccess(c -> log.info("Credential retrieved: id={}, userId={}", credentialId, userId))
                .doOnError(e -> log.error("Failed to retrieve credential: id={}, userId={}, error={}", credentialId, userId, e.getMessage()));
    }
}
