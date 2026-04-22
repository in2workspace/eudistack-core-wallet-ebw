package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;

import java.util.UUID;

@Service
public class ListPasskeysWorkflow {

    private final UserPasskeyRepository passkeyRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    public ListPasskeysWorkflow(UserPasskeyRepository passkeyRepository,
                                RefreshTokenRepository refreshTokenRepository) {
        this.passkeyRepository = passkeyRepository;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public Flux<PasskeyWithSessions> listPasskeys(UUID userId) {
        return passkeyRepository.findByUserId(userId)
                .flatMap(passkey -> refreshTokenRepository.countActiveByPasskeyId(passkey.getId())
                        .defaultIfEmpty(0L)
                        .map(count -> new PasskeyWithSessions(passkey, count)));
    }

    public record PasskeyWithSessions(UserPasskey passkey, long activeSessions) {}
}
