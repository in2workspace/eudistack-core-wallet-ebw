package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.exception.PasskeyNotFoundException;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.service.AuthTokenService;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * Attributes the caller's current session (its raw refresh token) to a passkey, so that
 * device-session bookkeeping (EUD-104 devices list) reflects the session that a device
 * just proved ownership of — via passkey creation or a WebAuthn assertion — rather than
 * leaving it unlinked (see {@link com.eudistack.ebw.domain.service.AuthTokenService#linkSessionToPasskey}).
 */
@Service
public class ConfirmPasskeySessionWorkflow {

    private final UserPasskeyRepository passkeyRepository;
    private final AuthTokenService authTokenService;

    public ConfirmPasskeySessionWorkflow(UserPasskeyRepository passkeyRepository,
                                         AuthTokenService authTokenService) {
        this.passkeyRepository = passkeyRepository;
        this.authTokenService = authTokenService;
    }

    public Mono<Void> confirmSession(UUID userId, UUID passkeyId, String rawRefreshToken) {
        return passkeyRepository.findByIdAndUserId(passkeyId, userId)
                .switchIfEmpty(Mono.error(new PasskeyNotFoundException()))
                .flatMap(passkey -> authTokenService.linkSessionToPasskey(rawRefreshToken, userId, passkey.getId()));
    }
}
