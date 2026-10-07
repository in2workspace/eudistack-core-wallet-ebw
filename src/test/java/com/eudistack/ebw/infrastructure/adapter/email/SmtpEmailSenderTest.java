package com.eudistack.ebw.infrastructure.adapter.email;

import com.eudistack.ebw.domain.service.TenantConfigService;
import jakarta.mail.Message;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.MessageSource;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;
import org.thymeleaf.context.IContext;
import org.thymeleaf.spring6.SpringTemplateEngine;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SmtpEmailSender} — tenant-specific sender address, rendered template and subject.
 */
@ExtendWith(MockitoExtension.class)
class SmtpEmailSenderTest {

    private static final String DEFAULT_FROM = "noreply@eudistack.com";

    @Mock private JavaMailSender mailSender;
    @Mock private SpringTemplateEngine templateEngine;
    @Mock private MessageSource messageSource;
    @Mock private TenantConfigService tenantConfigService;

    private SmtpEmailSender sender;

    @BeforeEach
    void setUp() {
        sender = new SmtpEmailSender(mailSender, templateEngine, messageSource, tenantConfigService, DEFAULT_FROM);
        when(mailSender.createMimeMessage()).thenReturn(new MimeMessage(Session.getInstance(new Properties())));
        when(templateEngine.process(eq("verification-code-email"), any(IContext.class))).thenReturn("<p>code</p>");
        when(messageSource.getMessage(eq("email.tx-code.subject"), isNull(), any())).thenReturn("Your code");
    }

    @Test
    void sendOtp_tenantMailFromConfigured_sendsTheRenderedMessageFromIt() throws Exception {
        // Arrange
        when(tenantConfigService.getStringOrDefault("ebw.mail_from", DEFAULT_FROM))
                .thenReturn(Mono.just("wallet@sandbox.example"));

        // Act
        var result = sender.sendOtp("holder@example.com", "123456");

        // Assert
        StepVerifier.create(result).verifyComplete();
        var sent = ArgumentCaptor.forClass(MimeMessage.class);
        verify(mailSender).send(sent.capture());
        assertThat(sent.getValue().getFrom()[0].toString()).isEqualTo("wallet@sandbox.example");
        assertThat(sent.getValue().getRecipients(Message.RecipientType.TO)[0].toString())
                .isEqualTo("holder@example.com");
        assertThat(sent.getValue().getSubject()).isEqualTo("Your code");
        var context = ArgumentCaptor.forClass(IContext.class);
        verify(templateEngine).process(eq("verification-code-email"), context.capture());
        assertThat(context.getValue().getVariable("txCode")).isEqualTo("123456");
    }

    @Test
    void sendOtp_smtpRejectsTheMessage_propagatesTheError() {
        // Arrange
        when(tenantConfigService.getStringOrDefault("ebw.mail_from", DEFAULT_FROM)).thenReturn(Mono.just(DEFAULT_FROM));
        doThrow(new MailSendException("relay denied")).when(mailSender).send(any(MimeMessage.class));

        // Act
        var result = sender.sendOtp("holder@example.com", "123456");

        // Assert
        StepVerifier.create(result).expectError(MailSendException.class).verify();
    }
}
