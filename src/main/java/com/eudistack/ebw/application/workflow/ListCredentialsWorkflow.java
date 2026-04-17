package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.model.WalletCredential;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;

import java.util.UUID;

@Service
public class ListCredentialsWorkflow {

    private final WalletCredentialRepository credentialRepository;

    public ListCredentialsWorkflow(WalletCredentialRepository credentialRepository) {
        this.credentialRepository = credentialRepository;
    }

    public Flux<WalletCredential> listCredentials(UUID userId, String status,
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
