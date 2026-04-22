package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.exception.CredentialNotFoundException;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import com.eudistack.ebw.domain.service.CredentialService;
import com.eudistack.ebw.domain.spi.CredentialEncryptor;
import com.eudistack.ebw.infrastructure.controller.dto.VerifiableCredentialResponse;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.UUID;

@Service
public class GetCredentialWorkflow {

    private final WalletCredentialRepository credentialRepository;
    private final CredentialEncryptor encryptor;
    private final CredentialService credentialService;

    public GetCredentialWorkflow(WalletCredentialRepository credentialRepository,
                                  CredentialEncryptor encryptor,
                                  CredentialService credentialService) {
        this.credentialRepository = credentialRepository;
        this.encryptor = encryptor;
        this.credentialService = credentialService;
    }

    public Mono<VerifiableCredentialResponse> getCredential(UUID userId, UUID credentialId) {
        return credentialRepository.findByIdAndUserId(credentialId, userId)
                .switchIfEmpty(Mono.error(new CredentialNotFoundException()))
                .flatMap(credential -> Mono
                        .fromCallable(() -> credentialService.toVerifiableCredential(credential, encryptor))
                        .subscribeOn(Schedulers.boundedElastic()));
    }
}
