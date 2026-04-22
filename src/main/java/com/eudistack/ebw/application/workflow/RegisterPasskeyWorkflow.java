package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.exception.DuplicatePasskeyException;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.spi.HashProvider;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

@Service
public class RegisterPasskeyWorkflow {

    private final UserPasskeyRepository passkeyRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AuditService auditService;
    private final HashProvider hashProvider;

    public RegisterPasskeyWorkflow(UserPasskeyRepository passkeyRepository,
                                   RefreshTokenRepository refreshTokenRepository,
                                   AuditService auditService,
                                   HashProvider hashProvider) {
        this.passkeyRepository = passkeyRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.auditService = auditService;
        this.hashProvider = hashProvider;
    }

    public Mono<UserPasskey> registerPasskey(UUID userId, String credentialId, String displayName,
                                             String userAgent) {
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
                                            .then(refreshTokenRepository.linkOrphanTokensToPasskey(userId, savedPasskey.getId()))
                                            .thenReturn(savedPasskey));
                }));
    }
}
