package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.WalletInstance;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.model.exception.WalletInstanceNotFoundException;
import com.eudistack.ebw.domain.model.exception.WalletInstanceRevokedException;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.repository.WalletInstanceRepository;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.spi.TransactionRunner;
import com.eudistack.ebw.support.TestPasskeys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link BindWalletInstanceWorkflow} (EUD-15 FR-05, FR-07, AC-05, AC-06; EUD-8 AD-11). */
@ExtendWith(MockitoExtension.class)
class BindWalletInstanceWorkflowTest {

    @Mock private WalletInstanceRepository instanceRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private WalletUserRepository userRepository;
    @Mock private UserPasskeyRepository passkeyRepository;
    @Mock private AuditService auditService;
    @Mock private TransactionRunner transactionRunner;
    @Mock private EmailLocales emailLocales;
    @Mock private WalletInstanceNotices notices;

    private BindWalletInstanceWorkflow workflow;
    private WalletUser user;
    private WalletSession session;
    private WalletInstance instance;

    @BeforeEach
    void setUp() {
        workflow = new BindWalletInstanceWorkflow(instanceRepository, refreshTokenRepository, userRepository,
                passkeyRepository, auditService, transactionRunner, emailLocales, notices);
        user = WalletUser.create("ana@example.com", new byte[WalletUser.USER_HANDLE_LENGTH]);
        session = new WalletSession(user.getId(), UUID.randomUUID(), UUID.randomUUID(), null);
        instance = WalletInstance.register(user.getId(), "Mac · Chrome", WalletInstance.DeviceType.DESKTOP,
                UUID.randomUUID());
        lenient().when(transactionRunner.inTransaction(any())).thenAnswer(inv -> inv.getArgument(0));
        lenient().when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());
        lenient().when(refreshTokenRepository.bindSession(session.sessionId(), instance.id())).thenReturn(Mono.just(1L));
        lenient().when(refreshTokenRepository.clearPasskeyNoticePending(session.sessionId())).thenReturn(Mono.just(false));
        lenient().when(emailLocales.rememberRequestLanguage(user.getId())).thenReturn(Mono.empty());
        lenient().when(notices.sessionBound(any(), any())).thenReturn(Mono.just(false));
    }

    @Test
    void bind_activeInstanceOfTheAccount_bindsTheSessionAndUpdatesTheLastUse() {
        // AC-05: no step for the user, the last use is set and no other instance is registered
        when(instanceRepository.touchIfActive(instance.id(), user.getId())).thenReturn(Mono.just(instance));

        StepVerifier.create(workflow.bind(session, instance.id())).expectNext(instance).verifyComplete();

        verify(refreshTokenRepository).bindSession(session.sessionId(), instance.id());
        verify(instanceRepository, never()).insert(any());
        verify(auditService).record(WalletInstanceAuditEvents.ENTITY_WALLET_INSTANCE, instance.id(),
                WalletInstanceAuditEvents.WALLET_INSTANCE_BOUND, user.getId(),
                Map.of("session_id", session.sessionId().toString()));
        verify(emailLocales).rememberRequestLanguage(user.getId());
        verify(notices, never()).passkeyAdded(any(), any(), any());
    }

    @Test
    void bind_instanceOfAnotherAccount_isNotFoundAndTraced() {
        // AC-06: answered exactly as an instance that does not exist
        when(instanceRepository.touchIfActive(instance.id(), user.getId())).thenReturn(Mono.empty());
        when(instanceRepository.findByIdAndUserId(instance.id(), user.getId())).thenReturn(Mono.empty());

        StepVerifier.create(workflow.bind(session, instance.id())).expectError(WalletInstanceNotFoundException.class)
                .verify();

        verify(refreshTokenRepository, never()).bindSession(any(), any());
        verify(auditService).record(WalletInstanceAuditEvents.ENTITY_WALLET_INSTANCE, instance.id(),
                WalletInstanceAuditEvents.WALLET_INSTANCE_BIND_REJECTED, user.getId(),
                Map.of("reason", "not_found", "session_id", session.sessionId().toString()));
    }

    @Test
    void bind_revokedInstance_isRevokedAndNeverReactivated() {
        // FR-07, FR-16
        var revoked = new WalletInstance(instance.id(), user.getId(), "Mac · Chrome", WalletInstance.DeviceType.DESKTOP,
                WalletInstance.Status.REVOKED, Instant.now(), null, Instant.now(), WalletInstance.RevokedBy.HOLDER,
                instance.registeredPasskeyId());
        when(instanceRepository.touchIfActive(instance.id(), user.getId())).thenReturn(Mono.empty());
        when(instanceRepository.findByIdAndUserId(instance.id(), user.getId())).thenReturn(Mono.just(revoked));

        StepVerifier.create(workflow.bind(session, instance.id())).expectError(WalletInstanceRevokedException.class)
                .verify();

        verify(refreshTokenRepository, never()).bindSession(any(), any());
        verify(auditService).record(WalletInstanceAuditEvents.ENTITY_WALLET_INSTANCE, instance.id(),
                WalletInstanceAuditEvents.WALLET_INSTANCE_BIND_REJECTED, user.getId(),
                Map.of("reason", "revoked", "session_id", session.sessionId().toString()));
    }

    @Test
    void bind_sessionThatAddedAPasskey_sendsTheNewPasskeyEmailOnce() {
        // EUD-8 AD-11, AC-07: bound to a device that already existed, the new-passkey email
        UserPasskey passkey = TestPasskeys.create(user.getId(), "cred-1", "Passkey", null);
        session = new WalletSession(user.getId(), session.sessionId(), passkey.getId(), null);
        when(instanceRepository.touchIfActive(instance.id(), user.getId())).thenReturn(Mono.just(instance));
        when(refreshTokenRepository.clearPasskeyNoticePending(session.sessionId())).thenReturn(Mono.just(true));
        when(userRepository.findById(user.getId())).thenReturn(Mono.just(user));
        when(passkeyRepository.findByIdAndUserId(passkey.getId(), user.getId())).thenReturn(Mono.just(passkey));
        when(notices.passkeyAdded(user, passkey.getId(), passkey.getCreatedAt())).thenReturn(Mono.empty());

        StepVerifier.create(workflow.bind(session, instance.id())).expectNext(instance).verifyComplete();

        verify(notices).passkeyAdded(user, passkey.getId(), passkey.getCreatedAt());
    }
}
