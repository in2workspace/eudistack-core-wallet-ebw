package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.service.AuditService;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Sends the new-passkey email of the sessions that added a passkey to an account that already had one and ended
 * (revoked, or expired by inactivity or maximum duration) without binding or registering a Wallet Instance (EUD-8
 * AD-11). The mark is taken with a conditional update, so two service instances never send it twice; a failed
 * email is traced and not retried.
 */
@Service
public class SendPendingPasskeyNoticesWorkflow {

    private final RefreshTokenRepository refreshTokenRepository;
    private final WalletUserRepository userRepository;
    private final WalletInstanceNotices notices;
    private final AuditService auditService;

    public SendPendingPasskeyNoticesWorkflow(RefreshTokenRepository refreshTokenRepository,
                                             WalletUserRepository userRepository, WalletInstanceNotices notices,
                                             AuditService auditService) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.notices = notices;
        this.auditService = auditService;
    }

    /** Requires the tenant in the Reactor context. Emits the number of emails attempted. */
    public Mono<Long> sendPending() {
        return refreshTokenRepository.takePendingNoticesOfEndedSessions()
                .concatMap(pending -> userRepository.findById(pending.userId())
                        .flatMap(user -> notices.passkeyAdded(user, pending.passkeyId(), pending.passkeyAddedAt()))
                        // The mark is already taken: a failure here is traced, and the next notices still go.
                        .onErrorResume(e -> auditService.record(AuthAuditEvents.ENTITY_PASSKEY, pending.passkeyId(),
                                        AuthAuditEvents.NEW_PASSKEY_NOTICE_FAILED, pending.userId(), Map.of())
                                .onErrorResume(auditError -> Mono.empty()))
                        .thenReturn(pending))
                .count();
    }
}
