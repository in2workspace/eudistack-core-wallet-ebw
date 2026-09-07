package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.exception.DuplicatePasskeyException;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.AuthTokenService;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

@Service
public class RegisterPasskeyWorkflow {

    private final UserPasskeyRepository passkeyRepository;
    private final AuditService auditService;
    private final AuthTokenService authTokenService;

    public RegisterPasskeyWorkflow(UserPasskeyRepository passkeyRepository,
                                   AuditService auditService,
                                   AuthTokenService authTokenService) {
        this.passkeyRepository = passkeyRepository;
        this.auditService = auditService;
        this.authTokenService = authTokenService;
    }

    /**
     * @param refreshToken the caller's current session, if the client wants it attributed to
     *                     the new passkey right away (EUD-104 devices list). Optional: linking
     *                     is best-effort and never fails passkey creation itself — a stale or
     *                     already-rotated token here just leaves the session unattributed,
     *                     same as if the client hadn't sent one.
     */
    public Mono<UserPasskey> registerPasskey(UUID userId, String credentialId, String displayName,
                                             String userAgent, String refreshToken) {
        return passkeyRepository.findByUserIdAndCredentialId(userId, credentialId)
                .flatMap(existing -> Mono.<UserPasskey>error(new DuplicatePasskeyException()))
                .switchIfEmpty(Mono.defer(() -> {
                    var passkey = UserPasskey.create(userId, credentialId, displayName, userAgent);
                    return passkeyRepository.save(passkey)
                            .flatMap(savedPasskey ->
                                    auditService.record("passkey",
                                                    savedPasskey.getId(),
                                                    "PASSKEY_CREATED",
                                                    userId,
                                                    Map.of("display_name", displayName))
                                            .then(linkSessionIfPresent(userId, refreshToken, savedPasskey.getId()))
                                            .thenReturn(savedPasskey));
                }));
    }

    private Mono<Void> linkSessionIfPresent(UUID userId, String refreshToken, UUID passkeyId) {
        if (refreshToken == null || refreshToken.isBlank()) {
            return Mono.empty();
        }
        return authTokenService.linkSessionToPasskey(refreshToken, userId, passkeyId)
                .onErrorResume(e -> Mono.empty());
    }
}
