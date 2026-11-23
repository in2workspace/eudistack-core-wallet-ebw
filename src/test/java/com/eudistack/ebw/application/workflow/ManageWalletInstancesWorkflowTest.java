package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.WalletInstance;
import com.eudistack.ebw.domain.model.WalletInstance.DeviceType;
import com.eudistack.ebw.domain.model.WalletInstance.RevokedBy;
import com.eudistack.ebw.domain.model.WalletInstance.Status;
import com.eudistack.ebw.domain.model.exception.InvalidWalletInstanceException;
import com.eudistack.ebw.domain.model.exception.WalletInstanceNotFoundException;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.eudistack.ebw.domain.repository.WalletInstanceRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.spi.TransactionRunner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the "Dispositivos" workflows (EUD-15 FR-09 to FR-19): {@link ListWalletInstancesWorkflow},
 * {@link RenameWalletInstanceWorkflow}, {@link RevokeWalletInstanceWorkflow}, {@link WalletInstanceRevoker} and
 * {@link RevokeInactiveWalletInstancesWorkflow}.
 */
@ExtendWith(MockitoExtension.class)
class ManageWalletInstancesWorkflowTest {

    @Mock private WalletInstanceRepository instanceRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private AuditService auditService;
    @Mock private TransactionRunner transactionRunner;

    private final UUID userId = UUID.randomUUID();
    private WalletInstanceRevoker revoker;

    @BeforeEach
    void setUp() {
        revoker = new WalletInstanceRevoker(instanceRepository, refreshTokenRepository, auditService);
        lenient().when(transactionRunner.inTransaction(any())).thenAnswer(inv -> inv.getArgument(0));
        lenient().when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());
    }

    private WalletInstance instance(String name, Instant lastUsedAt) {
        return new WalletInstance(UUID.randomUUID(), userId, name, DeviceType.DESKTOP, Status.ACTIVE,
                Instant.parse("2026-07-01T10:00:00Z"), lastUsedAt, null, null, UUID.randomUUID());
    }

    private WalletSession session(UUID currentInstanceId) {
        return new WalletSession(userId, UUID.randomUUID(), UUID.randomUUID(), currentInstanceId);
    }

    // --- List (FR-09, FR-10, FR-11, AC-11)

    @Test
    void list_threeDevices_currentFirstThenByLastUseDescending() {
        var old = instance("Windows · Edge", Instant.parse("2026-07-02T10:00:00Z"));
        var current = instance("iPhone · App instalada", Instant.parse("2026-08-01T10:00:00Z"));
        var recent = instance("Mac · Chrome", Instant.parse("2026-10-27T10:00:00Z"));
        when(instanceRepository.findActiveByUserId(userId)).thenReturn(Flux.just(old, current, recent));

        StepVerifier.create(new ListWalletInstancesWorkflow(instanceRepository).list(session(current.id())))
                .assertNext(list -> assertThat(list).extracting(WalletInstance::displayName)
                        .containsExactly("iPhone · App instalada", "Mac · Chrome", "Windows · Edge"))
                .verifyComplete();
    }

    // --- Rename (FR-12, AC-13)

    @Test
    void rename_validName_isTrimmedStoredAndTracedWithoutTheName() {
        var device = instance("Mac · Chrome", null);
        var renamed = new WalletInstance(device.id(), userId, "Mi portátil", DeviceType.DESKTOP, Status.ACTIVE,
                device.createdAt(), null, null, null, device.registeredPasskeyId());
        when(instanceRepository.renameIfActive(device.id(), userId, "Mi portátil")).thenReturn(Mono.just(renamed));

        StepVerifier.create(new RenameWalletInstanceWorkflow(instanceRepository, auditService)
                        .rename(session(null), device.id(), "  Mi portátil "))
                .expectNext(renamed)
                .verifyComplete();

        verify(auditService).record(WalletInstanceAuditEvents.ENTITY_WALLET_INSTANCE, device.id(),
                WalletInstanceAuditEvents.WALLET_INSTANCE_RENAMED, userId, Map.of());
    }

    @Test
    void rename_emptyOrTooLongName_isNotStored() {
        var workflow = new RenameWalletInstanceWorkflow(instanceRepository, auditService);

        StepVerifier.create(workflow.rename(session(null), UUID.randomUUID(), " "))
                .expectError(InvalidWalletInstanceException.class).verify();
        StepVerifier.create(workflow.rename(session(null), UUID.randomUUID(), "x".repeat(51)))
                .expectError(InvalidWalletInstanceException.class).verify();
        verify(instanceRepository, never()).renameIfActive(any(), any(), anyString());
    }

    @Test
    void rename_instanceOfAnotherAccountOrRevoked_isNotFound() {
        // AC-12
        var id = UUID.randomUUID();
        when(instanceRepository.renameIfActive(id, userId, "Nombre")).thenReturn(Mono.empty());

        StepVerifier.create(new RenameWalletInstanceWorkflow(instanceRepository, auditService)
                        .rename(session(null), id, "Nombre"))
                .expectError(WalletInstanceNotFoundException.class)
                .verify();
    }

    // --- Revoke by the holder (FR-13 to FR-17, AC-14, AC-15, AC-17)

    @Test
    void revoke_otherDevice_marksItRevokedEndsItsSessionsAndTracesIt() {
        var other = instance("Mac · Chrome", null);
        var endedSession = UUID.randomUUID();
        when(instanceRepository.findByIdAndUserId(other.id(), userId)).thenReturn(Mono.just(other));
        when(instanceRepository.revokeIfActive(other.id(), RevokedBy.HOLDER)).thenReturn(Mono.just(true));
        when(refreshTokenRepository.revokeByWalletInstanceId(other.id())).thenReturn(Flux.just(endedSession));

        StepVerifier.create(new RevokeWalletInstanceWorkflow(instanceRepository, revoker, transactionRunner)
                        .revoke(session(UUID.randomUUID()), other.id()))
                .expectNext(List.of(endedSession))
                .verifyComplete();

        var metadata = ArgumentCaptor.forClass(Map.class);
        verify(auditService).record(eq(WalletInstanceAuditEvents.ENTITY_WALLET_INSTANCE), eq(other.id()),
                eq(WalletInstanceAuditEvents.WALLET_INSTANCE_REVOKED), eq(userId), metadata.capture());
        assertThat(metadata.getValue()).containsEntry("revoked_by", "HOLDER").containsEntry("current", false);
        verify(transactionRunner).inTransaction(any());
    }

    @Test
    void revoke_currentDevice_tracesItAsTheCurrentOne() {
        var current = instance("iPhone · Safari", null);
        when(instanceRepository.findByIdAndUserId(current.id(), userId)).thenReturn(Mono.just(current));
        when(instanceRepository.revokeIfActive(current.id(), RevokedBy.HOLDER)).thenReturn(Mono.just(true));
        when(refreshTokenRepository.revokeByWalletInstanceId(current.id())).thenReturn(Flux.empty());

        StepVerifier.create(new RevokeWalletInstanceWorkflow(instanceRepository, revoker, transactionRunner)
                        .revoke(session(current.id()), current.id()))
                .expectNextCount(1)
                .verifyComplete();

        var metadata = ArgumentCaptor.forClass(Map.class);
        verify(auditService).record(any(), any(), eq(WalletInstanceAuditEvents.WALLET_INSTANCE_REVOKED), any(),
                metadata.capture());
        assertThat(metadata.getValue()).containsEntry("current", true);
    }

    @Test
    void revoke_alreadyRevoked_isAcceptedWithoutEffects() {
        var revoked = new WalletInstance(UUID.randomUUID(), userId, "Old", DeviceType.MOBILE, Status.REVOKED,
                Instant.now(), null, Instant.now(), RevokedBy.INACTIVITY, UUID.randomUUID());
        when(instanceRepository.findByIdAndUserId(revoked.id(), userId)).thenReturn(Mono.just(revoked));

        StepVerifier.create(new RevokeWalletInstanceWorkflow(instanceRepository, revoker, transactionRunner)
                        .revoke(session(null), revoked.id()))
                .expectNext(List.of())
                .verifyComplete();

        verify(instanceRepository, never()).revokeIfActive(any(), any());
        verify(refreshTokenRepository, never()).revokeByWalletInstanceId(any());
    }

    @Test
    void revoke_instanceOfAnotherAccount_isNotFoundAndChangesNothing() {
        // AC-12
        var id = UUID.randomUUID();
        when(instanceRepository.findByIdAndUserId(id, userId)).thenReturn(Mono.empty());

        StepVerifier.create(new RevokeWalletInstanceWorkflow(instanceRepository, revoker, transactionRunner)
                        .revoke(session(null), id))
                .expectError(WalletInstanceNotFoundException.class)
                .verify();

        verify(instanceRepository, never()).revokeIfActive(any(), any());
    }

    @Test
    void revoke_concurrentRevocationWon_endsNothingTwice() {
        var other = instance("Mac · Chrome", null);
        when(instanceRepository.findByIdAndUserId(other.id(), userId)).thenReturn(Mono.just(other));
        when(instanceRepository.revokeIfActive(other.id(), RevokedBy.HOLDER)).thenReturn(Mono.just(false));

        StepVerifier.create(new RevokeWalletInstanceWorkflow(instanceRepository, revoker, transactionRunner)
                        .revoke(session(null), other.id()))
                .expectNext(List.of())
                .verifyComplete();

        verify(auditService, never()).record(any(), any(), eq(WalletInstanceAuditEvents.WALLET_INSTANCE_REVOKED), any(),
                any());
    }

    // --- "It was not me" (FR-19)

    @Test
    void revokeRegisteredWith_devicesOfThePasskey_areRevokedAsDisavowal() {
        var passkeyId = UUID.randomUUID();
        var first = UUID.randomUUID();
        var second = UUID.randomUUID();
        when(instanceRepository.revokeActiveByRegisteredPasskey(passkeyId, RevokedBy.DISAVOWAL))
                .thenReturn(Flux.just(first, second));
        when(refreshTokenRepository.revokeByWalletInstanceId(any())).thenReturn(Flux.empty());

        StepVerifier.create(revoker.revokeRegisteredWith(passkeyId, userId)).verifyComplete();

        var metadata = ArgumentCaptor.forClass(Map.class);
        verify(auditService, org.mockito.Mockito.times(2)).record(eq(WalletInstanceAuditEvents.ENTITY_WALLET_INSTANCE),
                any(), eq(WalletInstanceAuditEvents.WALLET_INSTANCE_REVOKED), eq(userId), metadata.capture());
        assertThat(metadata.getAllValues()).allSatisfy(m -> assertThat(m).containsEntry("revoked_by", "DISAVOWAL"));
    }

    // --- Inactivity (FR-18, AC-18)

    @Test
    void revokeInactive_cutoff_isNinetyDaysAgoAndEachRevocationIsTracedWithoutActor() {
        var stale = instance("Windows · Edge", Instant.now().minus(java.time.Duration.ofDays(91)));
        var cutoff = ArgumentCaptor.forClass(Instant.class);
        when(instanceRepository.revokeInactiveBatch(cutoff.capture(), eq(500))).thenReturn(Flux.just(stale));
        when(refreshTokenRepository.revokeByWalletInstanceId(stale.id())).thenReturn(Flux.empty());

        StepVerifier.create(new RevokeInactiveWalletInstancesWorkflow(instanceRepository, revoker, transactionRunner)
                        .revokeInactive())
                .expectNext(1L)
                .verifyComplete();

        // 89 days of inactivity are still before the cutoff: the instance stays active
        assertThat(cutoff.getValue()).isBetween(Instant.now().minus(java.time.Duration.ofDays(90)).minusSeconds(5),
                Instant.now().minus(java.time.Duration.ofDays(90)).plusSeconds(5));
        var metadata = ArgumentCaptor.forClass(Map.class);
        verify(auditService).record(eq(WalletInstanceAuditEvents.ENTITY_WALLET_INSTANCE), eq(stale.id()),
                eq(WalletInstanceAuditEvents.WALLET_INSTANCE_REVOKED), eq(null), metadata.capture());
        assertThat(metadata.getValue()).containsEntry("revoked_by", "INACTIVITY");
    }

    @Test
    void revokeInactive_fullBatch_runsAnotherOne() {
        var batch = java.util.stream.IntStream.range(0, 500).mapToObj(i -> instance("d" + i, null)).toList();
        when(instanceRepository.revokeInactiveBatch(any(), eq(500)))
                .thenReturn(Flux.fromIterable(batch))
                .thenReturn(Flux.just(instance("last", null)));
        when(refreshTokenRepository.revokeByWalletInstanceId(any())).thenReturn(Flux.empty());

        StepVerifier.create(new RevokeInactiveWalletInstancesWorkflow(instanceRepository, revoker, transactionRunner)
                        .revokeInactive())
                .expectNext(501L)
                .verifyComplete();
    }
}
