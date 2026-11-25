package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;

import java.util.UUID;

/** The passkeys of the account, for the Signal API of the Wallet App (EUD-15 AD-4). */
@Service
public class ListPasskeysWorkflow {

    private final UserPasskeyRepository passkeyRepository;

    public ListPasskeysWorkflow(UserPasskeyRepository passkeyRepository) {
        this.passkeyRepository = passkeyRepository;
    }

    public Flux<UserPasskey> listPasskeys(UUID userId) {
        return passkeyRepository.findByUserId(userId);
    }
}
