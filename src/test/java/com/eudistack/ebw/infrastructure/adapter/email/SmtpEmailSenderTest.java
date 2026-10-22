package com.eudistack.ebw.infrastructure.adapter.email;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.model.audit.AuditEntry;
import com.eudistack.ebw.domain.model.audit.AuditResult;
import com.eudistack.ebw.domain.repository.TenantRegistryRepository;
import com.eudistack.ebw.domain.service.TenantConfigService;
import com.eudistack.ebw.infrastructure.adapter.audit.ExternalSystemAccessRecorder;
import com.eudistack.ebw.infrastructure.adapter.audit.RecordingAuditTrail;
import com.eudistack.ebw.infrastructure.adapter.properties.EmailBrandingProperties;
import com.eudistack.ebw.infrastructure.adapter.properties.EmailBrandingProperties.SocialLink;
import com.eudistack.ebw.infrastructure.adapter.properties.EmailBrandingProperties.TenantEmailBranding;
import com.eudistack.ebw.infrastructure.adapter.properties.OtpProperties;
import jakarta.mail.Address;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SmtpEmailSenderTest {

    private static final String TO = "user@example.com";

    private JavaMailSender mailSender;
    private TenantRegistryRepository tenantRegistryRepository;
    private final RecordingAuditTrail auditTrail = new RecordingAuditTrail();
    private SmtpEmailSender sender;

    @BeforeEach
    void setUp() {
        mailSender = mock(JavaMailSender.class);
        when(mailSender.createMimeMessage()).thenAnswer(inv -> new MimeMessage(Session.getInstance(new Properties())));

        TenantConfigService tenantConfigService = mock(TenantConfigService.class);
        when(tenantConfigService.getStringOrDefault(eq("ebw.mail_from"), anyString()))
                .thenReturn(Mono.just("wallet@dome.example"));

        tenantRegistryRepository = mock(TenantRegistryRepository.class);

        ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();
        messageSource.setBasename("messages");
        messageSource.setDefaultEncoding("UTF-8");

        var branding = new EmailBrandingResolver(new EmailBrandingProperties("https://assets.example.com/tenants", Map.of(
                "dome", new TenantEmailBranding(true, true, List.of(new SocialLink("github", "https://github.com/dome"))))));

        sender = new SmtpEmailSender(mailSender, VerificationCodeEmailTemplateTest.engine(), messageSource,
                tenantConfigService, tenantRegistryRepository, branding,
                new ExternalSystemAccessRecorder(auditTrail), new OtpProperties(6, Duration.ofMinutes(15), 5), "noreply@eudistack.com");
    }

    @Test
    void sendOtp_brandedTenant_namesTheTenantInTheSubjectAndAttachesItsSocialIcons() throws Exception {
        when(tenantRegistryRepository.findDisplayName("dome")).thenReturn(Mono.just("DOME"));

        MimeMessage message = send("dome");

        assertThat(message.getSubject()).isEqualTo("Your DOME verification code — Wallet");
        assertThat(message.getFrom()).extracting(Address::toString).containsExactly("wallet@dome.example");
        assertThat(message.getAllRecipients()).extracting(Address::toString).containsExactly(TO);
        String html = htmlOf(message);
        assertThat(html)
                .contains(">123456</span>")
                .contains("It expires in 15 minutes.")
                .contains("https://assets.example.com/tenants/dome/email/logo.png")
                .contains("cid:icon-github.png");
        assertThat(contentIds(message)).containsExactly("<icon-github.png>");
    }

    @Test
    void sendOtp_unregisteredTenantWithoutBranding_fallsBackToTheTenantIdAndHasNoImages() throws Exception {
        when(tenantRegistryRepository.findDisplayName("sandbox")).thenReturn(Mono.empty());

        MimeMessage message = send("sandbox");

        assertThat(message.getSubject()).isEqualTo("Your sandbox verification code — Wallet");
        assertThat(htmlOf(message)).doesNotContain("<img");
        assertThat(contentIds(message)).isEmpty();
    }

    @Test
    void sendOtp_smtpRejectsTheMessage_propagatesTheError() {
        when(tenantRegistryRepository.findDisplayName("dome")).thenReturn(Mono.just("DOME"));
        doThrow(new MailSendException("relay denied")).when(mailSender).send(any(MimeMessage.class));

        StepVerifier.create(sender.sendOtp(TO, "123456")
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, "dome")))
                .expectError(MailSendException.class)
                .verify();
    }

    @Test
    void sendOtp_smtpAccepts_stagesASuccessfulExternalSystemAccessWithoutTheRecipientOrTheCode() {
        when(tenantRegistryRepository.findDisplayName("dome")).thenReturn(Mono.just("DOME"));

        send("dome");

        AuditEntry entry = auditTrail.staged().getFirst();
        assertThat(entry.result()).isEqualTo(AuditResult.SUCCESS);
        assertThat(entry.details()).containsEntry("system_type", "MailProvider")
                .containsEntry("operation", "verification-code-email");
        assertThat(entry.toString()).doesNotContain(TO).doesNotContain("123456");
    }

    @Test
    void sendOtp_smtpRejectsTheMessage_stagesAFailedExternalSystemAccess() {
        when(tenantRegistryRepository.findDisplayName("dome")).thenReturn(Mono.just("DOME"));
        doThrow(new MailSendException("relay denied")).when(mailSender).send(any(MimeMessage.class));

        StepVerifier.create(sender.sendOtp(TO, "123456")
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, "dome")))
                .expectError(MailSendException.class)
                .verify();

        AuditEntry entry = auditTrail.staged().getFirst();
        assertThat(entry.result()).isEqualTo(AuditResult.FAILURE);
        assertThat(entry.reason()).isEqualTo("ErrorResponse");
    }

    private MimeMessage send(String tenant) {
        StepVerifier.create(sender.sendOtp(TO, "123456")
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, tenant)))
                .verifyComplete();
        ArgumentCaptor<MimeMessage> captor = ArgumentCaptor.forClass(MimeMessage.class);
        verify(mailSender).send(captor.capture());
        return captor.getValue();
    }

    /** HTML body: the first part of the multipart/related tree. */
    private static String htmlOf(MimeMessage message) throws Exception {
        message.saveChanges();
        Object content = message.getContent();
        while (content instanceof MimeMultipart multipart) {
            content = multipart.getBodyPart(0).getContent();
        }
        return (String) content;
    }

    private static List<String> contentIds(MimeMessage message) throws Exception {
        List<String> ids = new ArrayList<>();
        collectContentIds((MimeMultipart) message.getContent(), ids);
        return ids;
    }

    private static void collectContentIds(MimeMultipart multipart, List<String> ids) throws Exception {
        for (int i = 0; i < multipart.getCount(); i++) {
            var part = (MimeBodyPart) multipart.getBodyPart(i);
            if (part.getContent() instanceof MimeMultipart nested) {
                collectContentIds(nested, ids);
            } else if (part.getContentID() != null) {
                ids.add(part.getContentID());
            }
        }
    }
}
