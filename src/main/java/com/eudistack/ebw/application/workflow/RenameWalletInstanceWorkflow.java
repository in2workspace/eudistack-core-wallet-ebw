package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.WalletInstance;
import com.eudistack.ebw.domain.model.exception.InvalidWalletInstanceException;
import com.eudistack.ebw.domain.model.exception.WalletInstanceNotFoundException;
import com.eudistack.ebw.domain.repository.WalletInstanceRepository;
import com.eudistack.ebw.domain.service.AuditService;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

/**
 * Renames an active Wallet Instance of the account (EUD-15 FR-12): the name is trimmed and cannot be empty nor
 * longer than 50 characters. Another account's instance, or a revoked one, is not found. The trace carries the
 * instance, never the name nor the email.
 */
@Service
public class RenameWalletInstanceWorkflow {

    private final WalletInstanceRepository instanceRepository;
    private final AuditService auditService;

    public RenameWalletInstanceWorkflow(WalletInstanceRepository instanceRepository, AuditService auditService) {
        this.instanceRepository = instanceRepository;
        this.auditService = auditService;
    }

    public Mono<WalletInstance> rename(WalletSession session, UUID instanceId, String displayName) {
        var name = WalletInstance.normalizeDisplayName(displayName);
        if (name == null) {
            return Mono.error(new InvalidWalletInstanceException("displayName"));
        }
        return instanceRepository.renameIfActive(instanceId, session.userId(), name)
                .switchIfEmpty(Mono.error(new WalletInstanceNotFoundException()))
                .flatMap(renamed -> auditService.record(WalletInstanceAuditEvents.ENTITY_WALLET_INSTANCE, renamed.id(),
                                WalletInstanceAuditEvents.WALLET_INSTANCE_RENAMED, session.userId(), Map.of())
                        .thenReturn(renamed));
    }
}
