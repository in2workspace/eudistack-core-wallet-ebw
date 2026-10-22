package com.eudistack.ebw.infrastructure.adapter.audit;

import com.eudistack.ebw.domain.model.audit.AuditEntry;
import com.eudistack.ebw.domain.spi.AuditTrailPort;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

/** Test double that keeps what was staged and can simulate a broken audit channel. */
public class RecordingAuditTrail implements AuditTrailPort {

    private final List<AuditEntry> staged = new ArrayList<>();
    private boolean failing;

    public RecordingAuditTrail failing() {
        this.failing = true;
        return this;
    }

    public List<AuditEntry> staged() {
        return staged;
    }

    @Override
    public Mono<Void> stageInNewTransaction(AuditEntry entry) {
        if (failing) {
            return Mono.error(new IllegalStateException("audit channel down"));
        }
        return Mono.fromRunnable(() -> staged.add(entry));
    }
}
