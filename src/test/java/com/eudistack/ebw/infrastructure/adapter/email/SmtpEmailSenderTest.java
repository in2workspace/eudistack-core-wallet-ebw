package com.eudistack.ebw.infrastructure.adapter.email;

import com.eudistack.ebw.domain.model.AccountCreatedNotice;
import com.eudistack.ebw.domain.model.OnboardingAlert;
import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.repository.TenantRegistryRepository;
import com.eudistack.ebw.domain.service.TenantConfigService;
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
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
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
                new OtpProperties(6, Duration.ofMinutes(15), 5), "noreply@eudistack.com");
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
    void sendNewPasskeyNotice_brandedTenant_usesTheSameLayoutAndBrandingAsTheOtpEmail() throws Exception {
        when(tenantRegistryRepository.findDisplayName("dome")).thenReturn(Mono.just("DOME"));

        StepVerifier.create(sender.sendNewPasskeyNotice(TO)
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, "dome")))
                .verifyComplete();
        ArgumentCaptor<MimeMessage> captor = ArgumentCaptor.forClass(MimeMessage.class);
        verify(mailSender).send(captor.capture());
        MimeMessage message = captor.getValue();

        assertThat(message.getSubject()).isEqualTo("New passkey added to your Wallet account");
        assertThat(message.getFrom()).extracting(Address::toString).containsExactly("wallet@dome.example");
        assertThat(htmlOf(message))
                .contains("A new passkey has been added to your Wallet account.")
                .contains("https://assets.example.com/tenants/dome/email/logo.png")
                .contains("cid:icon-github.png");
        assertThat(contentIds(message)).containsExactly("<icon-github.png>");
    }

    @Test
    void sendOnboardingAlert_securityContact_getsTheMaskedEmailTheDateAndTheSystem() throws Exception {
        // Arrange: FR-32, the alert never carries the holder's full email
        when(tenantRegistryRepository.findDisplayName("cgcom")).thenReturn(Mono.just("CGCOM"));
        var alert = new OnboardingAlert(OnboardingAlert.mask("ana.garcia@cgcom.es"),
                Instant.parse("2026-10-30T09:42:00Z"), "portal-machine.cgcom.es");

        // Act
        StepVerifier.create(sender.sendOnboardingAlert("security@cgcom.es", alert, Locale.ENGLISH)
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, "cgcom")))
                .verifyComplete();

        // Assert
        ArgumentCaptor<MimeMessage> captor = ArgumentCaptor.forClass(MimeMessage.class);
        verify(mailSender).send(captor.capture());
        MimeMessage message = captor.getValue();
        assertThat(message.getSubject()).isEqualTo("Wallet onboarding not recognized — CGCOM");
        assertThat(message.getAllRecipients()).extracting(Address::toString).containsExactly("security@cgcom.es");
        assertThat(htmlOf(message))
                .contains("The holder of a***@cgcom.es has said they did not create their wallet.")
                .contains("Created: 30/10/2026 10:42")
                .contains("System that requested the onboarding: portal-machine.cgcom.es")
                .doesNotContain("ana.garcia");
    }

    @Test
    void sendAccountCreatedNotice_holder_getsTheDateTheSystemTheDeviceAndTheLink() throws Exception {
        // Arrange: FR-29
        when(tenantRegistryRepository.findDisplayName("cgcom")).thenReturn(Mono.just("CGCOM"));
        var notice = new AccountCreatedNotice(Instant.parse("2026-10-30T09:42:00Z"), "portal-machine.cgcom.es",
                "iPhone · Safari", "https://cgcom.eudistack.net/no-he-sido-yo/tok", Instant.parse("2026-11-06T09:42:00Z"));

        // Act
        StepVerifier.create(sender.sendAccountCreatedNotice("ana@cgcom.es", notice, Locale.ENGLISH)
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, "cgcom")))
                .verifyComplete();

        // Assert
        ArgumentCaptor<MimeMessage> captor = ArgumentCaptor.forClass(MimeMessage.class);
        verify(mailSender).send(captor.capture());
        MimeMessage message = captor.getValue();
        assertThat(message.getSubject()).isEqualTo("Your CGCOM wallet has been created");
        assertThat(htmlOf(message))
                .contains("On 30/10/2026 10:42 your wallet was created from portal-machine.cgcom.es")
                .contains("href=\"https://cgcom.eudistack.net/no-he-sido-yo/tok\"")
                .contains("The link expires on 06/11/2026.");
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
