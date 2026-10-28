package com.eudistack.ebw.infrastructure.configuration;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import com.eudistack.ebw.infrastructure.observability.CustomObservationHandler;
import io.micrometer.common.KeyValue;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import static org.assertj.core.api.Assertions.assertThat;

class ObservationConfigTest {

    private final ObservationConfig config = new ObservationConfig();
    private final Logger handlerLogger = (Logger) LoggerFactory.getLogger(CustomObservationHandler.class);
    private final Level originalLevel = handlerLogger.getLevel();

    @AfterEach
    void restoreLogLevel() {
        handlerLogger.setLevel(originalLevel);
    }

    @Test
    void globalObservationFilter_AnyObservation_AddsTheComponentTag() {
        Observation.Context context = new Observation.Context();

        config.globalObservationFilter().map(context);

        assertThat(context.getLowCardinalityKeyValue("component"))
                .isEqualTo(KeyValue.of("component", "wallet-ebw"));
    }

    @Test
    void registerCustomObservationHandler_DebugEnabled_HandlerSeesTheObservation() {
        handlerLogger.setLevel(Level.DEBUG);
        ObservationRegistry registry = ObservationRegistry.create();
        config.registerCustomObservationHandler(new CustomObservationHandler()).customize(registry);

        Observation observation = Observation.start("wallet.test", registry);
        observation.error(new IllegalStateException("boom"));
        observation.stop();

        assertThat(observation.isNoop()).isFalse();
    }

    @Test
    void customObservationHandler_DebugDisabled_DoesNotSupportTheContext() {
        handlerLogger.setLevel(Level.INFO);

        assertThat(new CustomObservationHandler().supportsContext(new Observation.Context())).isFalse();
    }
}
