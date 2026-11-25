package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.WalletInstance;
import com.eudistack.ebw.domain.model.WalletInstance.RevokedBy;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.eudistack.ebw.domain.repository.WalletInstanceRepository;
import com.eudistack.ebw.domain.service.AuditService;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.List;
import java.util.UUID;

/**
 * The effects of revoking a Wallet Instance, the same whoever revokes it (EUD-15 FR-14, FR-18, FR-19): the
 * instance is marked revoked, every session bound to it ends and {@code WALLET_INSTANCE_REVOKED} is traced with
 * who revoked it. Passkeys and attestations are not touched (FR-17). Must run inside the caller's transaction;
 * the caller forgets the cached state of the returned sessions after the commit.
 */
@Component
public class WalletInstanceRevoker {

    private final WalletInstanceRepository instanceRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AuditService auditService;

    public WalletInstanceRevoker(WalletInstanceRepository instanceRepository,
                                 RefreshTokenRepository refreshTokenRepository, AuditService auditService) {
        this.instanceRepository = instanceRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.auditService = auditService;
    }

    /**
     * Revokes an active instance. Emits the sessions it ended; nothing if it was already revoked (a concurrent
     * revocation won and traced it).
     *
     * @param current whether it is the instance of the session that asks for it (trace)
     */
    public Mono<List<UUID>> revoke(WalletInstance instance, RevokedBy revokedBy, UUID actorId, boolean current) {
        return instanceRepository.revokeIfActive(instance.id(), revokedBy)
                .flatMap(revoked -> Boolean.TRUE.equals(revoked)
                        ? endSessions(instance.id(), instance.userId(), revokedBy, actorId, current)
                        : Mono.just(List.<UUID>of()));
    }

    /**
     * The effects of an instance the caller has already marked revoked (inactivity batch, "it was not me").
     * Emits the sessions it ended.
     */
    public Mono<List<UUID>> afterMarkedRevoked(UUID instanceId, UUID userId, RevokedBy revokedBy, UUID actorId) {
        return endSessions(instanceId, userId, revokedBy, actorId, false);
    }

    /** Revokes, as {@code DISAVOWAL}, the active instances registered with the passkey. Emits the sessions ended. */
    public Flux<UUID> revokeRegisteredWith(UUID passkeyId, UUID userId) {
        // Read whole before the effects run: they use the same connection of the caller's transaction.
        return instanceRepository.revokeActiveByRegisteredPasskey(passkeyId, RevokedBy.DISAVOWAL)
                .collectList()
                .flatMapMany(Flux::fromIterable)
                .concatMap(instanceId -> afterMarkedRevoked(instanceId, userId, RevokedBy.DISAVOWAL, userId))
                .flatMapIterable(sessions -> sessions);
    }

    private Mono<List<UUID>> endSessions(UUID instanceId, UUID userId, RevokedBy revokedBy, UUID actorId,
                                         boolean current) {
        var metadata = new HashMap<String, Object>();
        metadata.put("revoked_by", revokedBy.name());
        metadata.put("current", current);
        metadata.put("user_id", userId.toString());
        return refreshTokenRepository.revokeByWalletInstanceId(instanceId)
                .collectList()
                .flatMap(sessions -> auditService.record(WalletInstanceAuditEvents.ENTITY_WALLET_INSTANCE, instanceId,
                                WalletInstanceAuditEvents.WALLET_INSTANCE_REVOKED, actorId, metadata)
                        .thenReturn(sessions));
    }
}
