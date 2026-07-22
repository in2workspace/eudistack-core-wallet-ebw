package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.WalletActivity;
import com.eudistack.ebw.domain.repository.WalletActivityRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;

import java.util.UUID;

@Service
public class ListActivityWorkflow {

    private static final Logger log = LoggerFactory.getLogger(ListActivityWorkflow.class);
    private static final int MAX_ENTRIES = 200;

    private final WalletActivityRepository activityRepository;

    public ListActivityWorkflow(WalletActivityRepository activityRepository) {
        this.activityRepository = activityRepository;
    }

    public Flux<WalletActivity> listActivity(UUID userId) {
        return activityRepository.findRecentByUserId(userId, MAX_ENTRIES)
                .doOnComplete(() -> log.info("Activity listed: userId={}", userId))
                .doOnError(e -> log.error("Failed to list activity: userId={}, error={}", userId, e.getMessage()));
    }
}
