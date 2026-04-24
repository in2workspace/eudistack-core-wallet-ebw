package com.eudistack.ebw.infrastructure.configuration.health;

import jakarta.mail.Session;
import jakarta.mail.Transport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.ReactiveHealthIndicator;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Health indicator that verifies SMTP connectivity.
 * Mirrors eudistack-core-issuer 3.4.4: selects "smtps" when SSL is enabled
 * or port is 465 (implicit TLS), otherwise plain "smtp". The default
 * Spring MailHealthIndicator always uses "smtp", which hangs on
 * implicit-TLS endpoints (e.g. AWS SES :465) and tumbles the aggregate
 * /health with SMTP DOWN. Tracked in EUDISTACK-168.
 */
@Component
public class SmtpHealthIndicator implements ReactiveHealthIndicator {

    private static final Logger log = LoggerFactory.getLogger(SmtpHealthIndicator.class);

    private final JavaMailSender mailSender;

    public SmtpHealthIndicator(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @Override
    public Mono<Health> health() {
        return Mono.fromCallable(() -> {
            try {
                if (mailSender instanceof JavaMailSenderImpl impl) {
                    Session session = impl.getSession();
                    String protocol = useSmtps(impl, session) ? "smtps" : "smtp";
                    try (Transport transport = session.getTransport(protocol)) {
                        transport.connect(impl.getHost(), impl.getPort(), impl.getUsername(), impl.getPassword());
                    }
                    return Health.up()
                            .withDetail("host", impl.getHost())
                            .withDetail("port", impl.getPort())
                            .withDetail("protocol", protocol)
                            .build();
                }
                return Health.unknown().withDetail("reason", "mailSender type not supported").build();
            } catch (Exception e) {
                log.debug("SMTP health check failed: {}", e.getMessage());
                return Health.down().withDetail("error", e.getMessage()).build();
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }

    private static boolean useSmtps(JavaMailSenderImpl impl, Session session) {
        if (impl.getPort() == 465) {
            return true;
        }
        String sslEnable = session.getProperty("mail.smtp.ssl.enable");
        return "true".equalsIgnoreCase(sslEnable);
    }
}
