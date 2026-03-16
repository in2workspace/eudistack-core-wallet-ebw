package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.exception.PasskeyNotFoundException;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Service
public class UpdatePasskeyWorkflow {

    private final UserPasskeyRepository passkeyRepository;

    public UpdatePasskeyWorkflow(UserPasskeyRepository passkeyRepository) {
        this.passkeyRepository = passkeyRepository;
    }

    public Mono<UserPasskey> updatePasskey(UUID userId, UUID passkeyId, String displayName) {
        return passkeyRepository.findByIdAndUserId(passkeyId, userId)
                .switchIfEmpty(Mono.error(new PasskeyNotFoundException()))
                .flatMap(passkey -> {
                    passkey.updateDisplayName(displayName);
                    return passkeyRepository.save(passkey);
                });
    }
}
