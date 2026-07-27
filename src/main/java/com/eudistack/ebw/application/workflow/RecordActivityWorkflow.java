package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.ActivityType;
import com.eudistack.ebw.domain.model.WalletActivity;
import com.eudistack.ebw.domain.repository.WalletActivityRepository;
import com.eudistack.ebw.domain.service.AuditService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class RecordActivityWorkflow {

    private static final Logger log = LoggerFactory.getLogger(RecordActivityWorkflow.class);

    private final WalletActivityRepository activityRepository;
    private final AuditService auditService;

    public RecordActivityWorkflow(WalletActivityRepository activityRepository, AuditService auditService) {
        this.activityRepository = activityRepository;
        this.auditService = auditService;
    }

    public Mono<WalletActivity> recordActivity(UUID userId, UUID activityId, ActivityType type,
                                                String credentialName, String counterparty,
                                                String details, List<String> sharedAttributes) {
        var activity = new WalletActivity(activityId, userId, type, credentialName, counterparty,
                details, sharedAttributes, Instant.now());

        return activityRepository.insertIfAbsent(activity)
                .flatMap(saved -> auditService.record("activity", saved.getId(), saved.getType().name(), userId,
                                Map.of("credential_name", saved.getCredentialName(),
                                        "counterparty", saved.getCounterparty()))
                        .thenReturn(saved))
                .switchIfEmpty(Mono.just(activity))
                .doOnSuccess(a -> log.info("Activity recorded: id={}, userId={}, type={}", activityId, userId, type))
                .doOnError(e -> log.error("Failed to record activity: id={}, userId={}, error={}", activityId, userId, e.getMessage()));
    }
}
