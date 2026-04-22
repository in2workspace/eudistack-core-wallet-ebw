package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.model.WalletCredential;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import com.eudistack.ebw.domain.service.CredentialService;
import com.eudistack.ebw.domain.spi.CredentialEncryptor;
import com.eudistack.ebw.infrastructure.controller.dto.VerifiableCredentialResponse;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.UUID;

@Service
public class ListCredentialsWorkflow {

    private final WalletCredentialRepository credentialRepository;
    private final CredentialService credentialService;
    private final CredentialEncryptor encryptor;

    public ListCredentialsWorkflow(WalletCredentialRepository credentialRepository,
                                    CredentialService credentialService,
                                    CredentialEncryptor encryptor) {
        this.credentialRepository = credentialRepository;
        this.credentialService = credentialService;
        this.encryptor = encryptor;
    }

    public Flux<VerifiableCredentialResponse> listCredentials(UUID userId, String status,
                                                               String credentialConfigId, String issuer) {
        return resolveCredentials(userId, status, credentialConfigId, issuer)
                .flatMap(credential -> Mono
                        .fromCallable(() -> credentialService.toVerifiableCredential(credential, encryptor))
                        .subscribeOn(Schedulers.boundedElastic()));
    }

    private Flux<WalletCredential> resolveCredentials(UUID userId, String status,
                                                       String credentialConfigId, String issuer) {
        if (status == null && credentialConfigId == null && issuer == null) {
            return credentialRepository.findAllByUserId(userId);
        }

        CredentialStatus statusEnum = null;
        if (status != null) {
            try {
                statusEnum = CredentialStatus.valueOf(status);
            } catch (IllegalArgumentException e) {
                return Flux.error(new IllegalArgumentException("Invalid status filter: " + status));
            }
        }

        return credentialRepository.findAllByUserIdAndFilters(userId, statusEnum, credentialConfigId, issuer);
    }
}
