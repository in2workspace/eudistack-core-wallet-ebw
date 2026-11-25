package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.WalletInstance;
import com.eudistack.ebw.domain.model.exception.WalletInstanceNotFoundException;
import com.eudistack.ebw.domain.model.exception.WalletInstanceRevokedException;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.repository.WalletInstanceRepository;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.spi.TransactionRunner;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

/**
 * Binds the session to the Wallet Instance the Wallet App remembers (EUD-15 FR-05, FR-07, design §2.1), without
 * any step for the user. Only an active instance of the account of the session: one of another account is
 * answered as not found, and a revoked one as revoked, so the Wallet App forgets it and registers a new one; both
 * are traced. The last use is set in the same conditional statement that checks the instance is active, so a
 * concurrent revocation wins. A passkey registered with an onboarding ticket that still owes its new-account email
 * gets it now, with the name of the device (EUD-15 FR-08); otherwise, if the session added a passkey to an account
 * that already had one, the new-passkey email goes now (EUD-8 AD-11).
 */
@Service
public class BindWalletInstanceWorkflow {

    private final WalletInstanceRepository instanceRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final WalletUserRepository userRepository;
    private final UserPasskeyRepository passkeyRepository;
    private final AuditService auditService;
    private final TransactionRunner transactionRunner;
    private final EmailLocales emailLocales;
    private final WalletInstanceNotices notices;

    @SuppressWarnings("java:S107")
    public BindWalletInstanceWorkflow(WalletInstanceRepository instanceRepository,
                                      RefreshTokenRepository refreshTokenRepository,
                                      WalletUserRepository userRepository, UserPasskeyRepository passkeyRepository,
                                      AuditService auditService, TransactionRunner transactionRunner,
                                      EmailLocales emailLocales, WalletInstanceNotices notices) {
        this.instanceRepository = instanceRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.passkeyRepository = passkeyRepository;
        this.auditService = auditService;
        this.transactionRunner = transactionRunner;
        this.emailLocales = emailLocales;
        this.notices = notices;
    }

    /**
     * @throws WalletInstanceNotFoundException (signal) no instance with that id in the account
     * @throws WalletInstanceRevokedException  (signal) the instance is revoked
     */
    public Mono<WalletInstance> bind(WalletSession session, UUID instanceId) {
        return transactionRunner.inTransaction(instanceRepository.touchIfActive(instanceId, session.userId())
                        .flatMap(instance -> refreshTokenRepository.bindSession(session.sessionId(), instance.id())
                                .then(auditService.record(WalletInstanceAuditEvents.ENTITY_WALLET_INSTANCE,
                                        instance.id(), WalletInstanceAuditEvents.WALLET_INSTANCE_BOUND,
                                        session.userId(), Map.of("session_id", session.sessionId().toString())))
                                .thenReturn(instance)))
                .switchIfEmpty(Mono.defer(() -> reject(session, instanceId)))
                .flatMap(instance -> emailLocales.rememberRequestLanguage(session.userId())
                        .then(notices.sessionBound(session.passkeyId(), instance)
                                .filter(sentAsOnboarding -> !sentAsOnboarding)
                                .flatMap(notOnboarding -> notifyPendingPasskey(session)))
                        .thenReturn(instance));
    }

    private Mono<WalletInstance> reject(WalletSession session, UUID instanceId) {
        return instanceRepository.findByIdAndUserId(instanceId, session.userId())
                .map(existing -> "revoked")
                .defaultIfEmpty("not_found")
                .flatMap(reason -> auditService.record(WalletInstanceAuditEvents.ENTITY_WALLET_INSTANCE, instanceId,
                                WalletInstanceAuditEvents.WALLET_INSTANCE_BIND_REJECTED, session.userId(),
                                Map.of("reason", reason, "session_id", session.sessionId().toString()))
                        .then(Mono.error("revoked".equals(reason)
                                ? new WalletInstanceRevokedException()
                                : new WalletInstanceNotFoundException())));
    }

    /** The mark is taken by one call only, so the email goes once. */
    private Mono<Void> notifyPendingPasskey(WalletSession session) {
        return refreshTokenRepository.clearPasskeyNoticePending(session.sessionId())
                .filter(Boolean::booleanValue)
                .flatMap(taken -> Mono.zip(userRepository.findById(session.userId()),
                        passkeyRepository.findByIdAndUserId(session.passkeyId(), session.userId())))
                .flatMap(tuple -> notices.passkeyAdded(tuple.getT1(), tuple.getT2().getId(),
                        tuple.getT2().getCreatedAt()));
    }
}
