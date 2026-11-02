package com.eudistack.ebw.infrastructure.observability;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Debug log of every observation's lifecycle (start, error, stop). Records no metrics, so no
 * counter is duplicated. Only takes part while this logger is at DEBUG: otherwise it costs nothing.
 */
@Component
public class CustomObservationHandler implements ObservationHandler<Observation.Context> {

    private static final Logger log = LoggerFactory.getLogger(CustomObservationHandler.class);

    @Override
    public void onStart(Observation.Context context) {
        log.debug("Starting observation: {}", context.getName());
    }

    @Override
    public void onError(Observation.Context context) {
        log.debug("Error in observation {}: {}",
                context.getName(),
                context.getError() != null ? context.getError().getMessage() : "unknown");
    }

    @Override
    public void onStop(Observation.Context context) {
        log.debug("Finished observation: {}", context.getName());
    }

    @Override
    public boolean supportsContext(Observation.Context context) {
        return log.isDebugEnabled();
    }
}
