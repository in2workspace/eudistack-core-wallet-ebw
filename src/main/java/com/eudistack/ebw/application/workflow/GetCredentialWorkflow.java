package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.WalletCredential;
import com.eudistack.ebw.domain.model.exception.CredentialNotFoundException;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import com.eudistack.ebw.domain.spi.CredentialEncryptor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Service
public class GetCredentialWorkflow {

    private final WalletCredentialRepository credentialRepository;
    private final CredentialEncryptor encryptor;

    public GetCredentialWorkflow(WalletCredentialRepository credentialRepository,
                                  CredentialEncryptor encryptor) {
        this.credentialRepository = credentialRepository;
        this.encryptor = encryptor;
    }

    public Mono<WalletCredential> getCredential(UUID userId, UUID credentialId) {
        return credentialRepository.findByIdAndUserId(credentialId, userId)
                .switchIfEmpty(Mono.error(new CredentialNotFoundException()))
                .map(credential -> {
                    var decrypted = encryptor.decrypt(credential.getCredentialRaw());
                    credential.setCredentialRaw(decrypted);
                    return credential;
                });
    }
}
