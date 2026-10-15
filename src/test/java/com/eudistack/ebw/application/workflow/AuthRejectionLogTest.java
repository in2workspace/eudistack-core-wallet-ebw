package com.eudistack.ebw.application.workflow;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.eudistack.ebw.domain.model.AuthRejectionReason;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

class AuthRejectionLogTest {

    private Logger logger;
    private Level previousLevel;
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void setUp() {
        logger = (Logger) LoggerFactory.getLogger(AuthRejectionLogTest.class);
        previousLevel = logger.getLevel();
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void tearDown() {
        logger.detachAppender(appender);
        logger.setLevel(previousLevel);
    }

    @Test
    void log_infoEnabled_logsTheFixedReasonCode() {
        logger.setLevel(Level.INFO);

        AuthRejectionLog.log(logger, "Sign-in", AuthRejectionReason.PRF_UNSUPPORTED);

        assertThat(appender.list).singleElement()
                .satisfies(event -> assertThat(event.getFormattedMessage())
                        .isEqualTo("Sign-in rejected: " + AuthRejectionReason.PRF_UNSUPPORTED.code()));
    }

    @Test
    void log_infoDisabled_logsNothing() {
        logger.setLevel(Level.ERROR);

        AuthRejectionLog.log(logger, "Sign-in", AuthRejectionReason.PRF_UNSUPPORTED);

        assertThat(appender.list).isEmpty();
    }

    @Test
    void detail_debugEnabledLongMessage_logsTruncatedDetail() {
        logger.setLevel(Level.DEBUG);

        AuthRejectionLog.detail(logger, "Sign-in", new IllegalStateException("x".repeat(500)));

        assertThat(appender.list).singleElement()
                .satisfies(event -> assertThat(event.getFormattedMessage())
                        .isEqualTo("Sign-in rejection detail: " + "x".repeat(200)));
    }

    @Test
    void detail_debugDisabled_logsNothing() {
        logger.setLevel(Level.INFO);

        AuthRejectionLog.detail(logger, "Sign-in", new IllegalStateException("boom"));

        assertThat(appender.list).isEmpty();
    }
}
