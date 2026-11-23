package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.WalletInstance;
import com.eudistack.ebw.domain.repository.WalletInstanceRepository;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/**
 * The active Wallet Instances of the account of the session (EUD-15 FR-09 to FR-11): revoked ones are not
 * listed. The instance of the session first, then by last use, the most recent first.
 */
@Service
public class ListWalletInstancesWorkflow {

    private final WalletInstanceRepository instanceRepository;

    public ListWalletInstancesWorkflow(WalletInstanceRepository instanceRepository) {
        this.instanceRepository = instanceRepository;
    }

    public Mono<List<WalletInstance>> list(WalletSession session) {
        Comparator<WalletInstance> currentFirst = Comparator.comparing(
                instance -> !Objects.equals(instance.id(), session.walletInstanceId()));
        Comparator<WalletInstance> lastUsedDescending = Comparator.comparing(
                (WalletInstance instance) -> instance.lastUsedAt() == null ? instance.createdAt() : instance.lastUsedAt(),
                Comparator.nullsLast(Comparator.<Instant>reverseOrder()));
        return instanceRepository.findActiveByUserId(session.userId())
                .collectSortedList(currentFirst.thenComparing(lastUsedDescending));
    }
}
