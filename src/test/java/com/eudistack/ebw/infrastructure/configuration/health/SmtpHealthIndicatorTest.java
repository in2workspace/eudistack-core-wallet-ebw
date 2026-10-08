package com.eudistack.ebw.infrastructure.configuration.health;

import jakarta.mail.NoSuchProviderException;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.Status;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SmtpHealthIndicator} — protocol selection (smtps on :465 or ssl.enable) and
 * UP / DOWN / UNKNOWN mapping. The mail {@link Session} and {@link Transport} are mocked: no network.
 */
class SmtpHealthIndicatorTest {

    private JavaMailSenderImpl mailSender;
    private Session session;
    private Transport transport;

    @BeforeEach
    void setUp() {
        mailSender = mock(JavaMailSenderImpl.class);
        session = mock(Session.class);
        transport = mock(Transport.class);
        when(mailSender.getSession()).thenReturn(session);
        when(mailSender.getHost()).thenReturn("smtp.example");
        when(mailSender.getUsername()).thenReturn("user");
        when(mailSender.getPassword()).thenReturn("secret");
    }

    @Test
    void health_implicitTlsPort465_connectsWithSmtpsAndReportsUp() throws Exception {
        // Arrange
        when(mailSender.getPort()).thenReturn(465);
        when(session.getTransport("smtps")).thenReturn(transport);

        // Act
        var result = new SmtpHealthIndicator(mailSender).health();

        // Assert
        StepVerifier.create(result)
                .assertNext(health -> {
                    assertThat(health.getStatus()).isEqualTo(Status.UP);
                    assertThat(health.getDetails())
                            .containsEntry("host", "smtp.example")
                            .containsEntry("port", 465)
                            .containsEntry("protocol", "smtps");
                })
                .verifyComplete();
        verify(transport).connect("smtp.example", 465, "user", "secret");
        verify(transport).close();
    }

    @Test
    void health_sslEnabledOnOtherPort_usesSmtps() throws Exception {
        // Arrange
        when(mailSender.getPort()).thenReturn(2465);
        when(session.getProperty("mail.smtp.ssl.enable")).thenReturn("TRUE");
        when(session.getTransport("smtps")).thenReturn(transport);

        // Act
        var result = new SmtpHealthIndicator(mailSender).health();

        // Assert
        StepVerifier.create(result)
                .assertNext(health -> assertThat(health.getDetails()).containsEntry("protocol", "smtps"))
                .verifyComplete();
    }

    @Test
    void health_startTlsPort587_usesPlainSmtp() throws Exception {
        // Arrange
        when(mailSender.getPort()).thenReturn(587);
        when(session.getProperty("mail.smtp.ssl.enable")).thenReturn(null);
        when(session.getTransport("smtp")).thenReturn(transport);

        // Act
        var result = new SmtpHealthIndicator(mailSender).health();

        // Assert
        StepVerifier.create(result)
                .assertNext(health -> {
                    assertThat(health.getStatus()).isEqualTo(Status.UP);
                    assertThat(health.getDetails()).containsEntry("protocol", "smtp");
                })
                .verifyComplete();
    }

    @Test
    void health_transportUnavailable_reportsDownWithTheError() throws Exception {
        // Arrange
        when(mailSender.getPort()).thenReturn(587);
        when(session.getTransport("smtp")).thenThrow(new NoSuchProviderException("no provider"));

        // Act
        var result = new SmtpHealthIndicator(mailSender).health();

        // Assert
        StepVerifier.create(result)
                .assertNext(health -> {
                    assertThat(health.getStatus()).isEqualTo(Status.DOWN);
                    assertThat(health.getDetails()).containsEntry("error", "no provider");
                })
                .verifyComplete();
    }

    @Test
    void health_nonJavaMailSenderImpl_reportsUnknown() {
        // Arrange
        var indicator = new SmtpHealthIndicator(mock(JavaMailSender.class));

        // Act
        var result = indicator.health();

        // Assert
        StepVerifier.create(result)
                .assertNext(health -> {
                    assertThat(health.getStatus()).isEqualTo(Status.UNKNOWN);
                    assertThat(health.getDetails()).containsEntry("reason", "mailSender type not supported");
                })
                .verifyComplete();
    }
}
