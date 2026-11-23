package com.eudistack.ebw.infrastructure.adapter.email;

import com.eudistack.ebw.domain.model.AccountCompleteNotice;
import com.eudistack.ebw.domain.model.AccountCreatedNotice;
import com.eudistack.ebw.domain.model.EmailSettings;
import com.eudistack.ebw.domain.model.NewDeviceNotice;
import com.eudistack.ebw.domain.model.NewPasskeyNotice;
import com.eudistack.ebw.domain.model.OnboardingAlert;
import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.model.audit.AuditEntry;
import com.eudistack.ebw.domain.model.audit.AuditResult;
import com.eudistack.ebw.domain.repository.TenantRegistryRepository;
import com.eudistack.ebw.domain.service.EmailSettingsService;
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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
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

/**
 * Unit tests for {@link SmtpEmailSender}: the content of the wireframes of EUD-8 and EUD-15, in the language the
 * caller chooses (es, ca, en; FR-38), with the dates in the tenant's {@code ebw.timezone} and the tenant's branding.
 */
class SmtpEmailSenderTest {

    private static final String TO = "user@example.com";
    private static final Locale ES = Locale.of("es");
    private static final Locale CA = Locale.of("ca");
    /** 09:42 UTC is 10:42 in Madrid on that date (CET). */
    private static final Instant AT = Instant.parse("2026-10-30T09:42:00Z");
    private static final String DEVICES = "https://cgcom.eudistack.net/wallet/tabs/devices";

    private JavaMailSender mailSender;
    private TenantRegistryRepository tenantRegistryRepository;
    private EmailSettingsService emailSettingsService;
    private final RecordingAuditTrail auditTrail = new RecordingAuditTrail();
    private SmtpEmailSender sender;

    @BeforeEach
    void setUp() {
        mailSender = mock(JavaMailSender.class);
        when(mailSender.createMimeMessage()).thenAnswer(inv -> new MimeMessage(Session.getInstance(new Properties())));

        TenantConfigService tenantConfigService = mock(TenantConfigService.class);
        when(tenantConfigService.getStringOrDefault(eq("ebw.mail_from"), anyString()))
                .thenReturn(Mono.just("wallet@dome.example"));

        emailSettingsService = mock(EmailSettingsService.class);
        when(emailSettingsService.current()).thenReturn(Mono.just(EmailSettings.DEFAULTS));

        tenantRegistryRepository = mock(TenantRegistryRepository.class);

        var branding = new EmailBrandingResolver(new EmailBrandingProperties("https://assets.example.com/tenants", Map.of(
                "dome", new TenantEmailBranding(true, true, List.of(new SocialLink("github", "https://github.com/dome"))))));

        sender = new SmtpEmailSender(mailSender, VerificationCodeEmailTemplateTest.engine(), messageSource(),
                tenantConfigService, emailSettingsService, tenantRegistryRepository, branding,
                new ExternalSystemAccessRecorder(auditTrail), new OtpProperties(6, Duration.ofMinutes(15), 5),
                "noreply@eudistack.com");
    }

    /** As configured in application.yaml (spring.messages). */
    static ResourceBundleMessageSource messageSource() {
        ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();
        messageSource.setBasename("messages");
        messageSource.setDefaultEncoding("UTF-8");
        messageSource.setFallbackToSystemLocale(false);
        messageSource.setAlwaysUseMessageFormat(true);
        return messageSource;
    }

    // --- Código de acceso ---

    @Test
    void sendOtp_brandedTenant_namesTheTenantInTheSubjectAndAttachesItsSocialIcons() throws Exception {
        when(tenantRegistryRepository.findDisplayName("dome")).thenReturn(Mono.just("DOME"));

        MimeMessage message = send("dome", ES);

        assertThat(message.getSubject()).isEqualTo("Tu código para entrar en DOME");
        assertThat(message.getFrom()).extracting(Address::toString).containsExactly("wallet@dome.example");
        assertThat(message.getAllRecipients()).extracting(Address::toString).containsExactly(TO);
        assertThat(htmlOf(message))
                .contains(">123456</span>")
                .contains("Tu código es:")
                .contains("Caduca en 15 minutos.")
                .contains("nadie puede entrar sin el código")
                .contains("https://assets.example.com/tenants/dome/email/logo.png")
                .contains("cid:icon-github.png")
                .doesNotContain("Revisar mis dispositivos");
        assertThat(contentIds(message)).containsExactly("<icon-github.png>");
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "ca|El teu codi per entrar a DOME|Caduca d&#39;aquí a 15 minuts.|ningú no pot entrar sense el codi",
            "en|Your code to sign in to DOME|It expires in 15 minutes.|nobody can sign in without the code"})
    // Thymeleaf writes an apostrophe as &#39;
    void sendOtp_languageOfTheRequest_isWrittenInIt(String language, String subject, String hint, String footer)
            throws Exception {
        // AC-32 of EUD-8: a Wallet App in Catalan gets the code in Catalan
        when(tenantRegistryRepository.findDisplayName("dome")).thenReturn(Mono.just("DOME"));

        MimeMessage message = send("dome", Locale.of(language));

        assertThat(message.getSubject()).isEqualTo(subject);
        assertThat(htmlOf(message)).contains(hint).contains(footer).contains("lang=\"" + language + "\"");
    }

    @Test
    void sendOtp_unregisteredTenantWithoutBranding_fallsBackToTheTenantIdAndHasNoImages() throws Exception {
        when(tenantRegistryRepository.findDisplayName("sandbox")).thenReturn(Mono.empty());

        MimeMessage message = send("sandbox", ES);

        assertThat(message.getSubject()).isEqualTo("Tu código para entrar en sandbox");
        assertThat(htmlOf(message)).doesNotContain("<img");
        assertThat(contentIds(message)).isEmpty();
    }

    // --- Passkey nueva ---

    @Test
    void sendNewPasskeyNotice_holder_getsTheDateInTheTenantZoneAndTheDevicesButton() throws Exception {
        when(tenantRegistryRepository.findDisplayName("dome")).thenReturn(Mono.just("DOME"));

        MimeMessage message = capture(sender.sendNewPasskeyNotice(TO, new NewPasskeyNotice(AT, DEVICES), ES), "dome");

        assertThat(message.getSubject()).isEqualTo("Se ha añadido una passkey a tu wallet");
        assertThat(htmlOf(message))
                .contains("El 30/10/2026 a las 10:42 se añadió una passkey nueva a tu wallet.")
                .contains("Si no, entra en tu wallet y revisa tus dispositivos.")
                .contains("href=\"" + DEVICES + "\"")
                .contains("Revisar mis dispositivos")
                .contains("cid:icon-github.png");
    }

    @Test
    void sendNewPasskeyNotice_tenantWithoutWalletUrl_goesWithoutTheButton() throws Exception {
        when(tenantRegistryRepository.findDisplayName("dome")).thenReturn(Mono.just("DOME"));

        MimeMessage message = capture(sender.sendNewPasskeyNotice(TO, new NewPasskeyNotice(AT, null), ES), "dome");

        assertThat(htmlOf(message)).doesNotContain("Revisar mis dispositivos").doesNotContain("href=\"https://cgcom");
    }

    @Test
    void sendNewPasskeyNotice_otherTimeZone_writesTheDateInIt() throws Exception {
        // EUD-8 design §2.8: dates in ebw.timezone of the tenant
        when(tenantRegistryRepository.findDisplayName("dome")).thenReturn(Mono.just("DOME"));
        when(emailSettingsService.current())
                .thenReturn(Mono.just(new EmailSettings("es", ZoneId.of("Atlantic/Canary"))));

        MimeMessage message = capture(sender.sendNewPasskeyNotice(TO, new NewPasskeyNotice(AT, DEVICES), ES), "dome");

        assertThat(htmlOf(message)).contains("El 30/10/2026 a las 09:42");
    }

    // --- Alta completa ---

    @Test
    void sendAccountCompleteNotice_firstDevice_namesTheDeviceWithoutLinks() throws Exception {
        when(tenantRegistryRepository.findDisplayName("cgcom")).thenReturn(Mono.just("CGCOM"));

        MimeMessage message = capture(sender.sendAccountCompleteNotice(TO,
                new AccountCompleteNotice(AT, "iPhone · Safari"), ES), "cgcom");

        assertThat(message.getSubject()).isEqualTo("Tu wallet de CGCOM está listo");
        assertThat(htmlOf(message))
                .contains("Has creado tu wallet el 30/10/2026 a las 10:42 en el dispositivo «iPhone · Safari».")
                .contains("Puedes ver tus dispositivos en Ajustes, Dispositivos.")
                .doesNotContain("Revisar mis dispositivos")
                .doesNotContain("<a ");
    }

    @Test
    void sendAccountCompleteNotice_nameWithMarkup_isEscaped() throws Exception {
        // The name is typed in the Wallet App: it is text, never markup
        when(tenantRegistryRepository.findDisplayName("cgcom")).thenReturn(Mono.just("CGCOM"));

        MimeMessage message = capture(sender.sendAccountCompleteNotice(TO,
                new AccountCompleteNotice(AT, "<a href=\"https://evil.example\">x</a>"), ES), "cgcom");

        assertThat(htmlOf(message)).doesNotContain("<a href=\"https://evil.example\">").contains("&lt;a href=");
    }

    // --- Dispositivo nuevo ---

    @Test
    void sendNewDeviceNotice_withoutPasskey_namesTheDeviceAndLinksToDevices() throws Exception {
        when(tenantRegistryRepository.findDisplayName("cgcom")).thenReturn(Mono.just("CGCOM"));

        MimeMessage message = capture(sender.sendNewDeviceNotice(TO,
                new NewDeviceNotice(AT, "Windows · Edge", false, DEVICES), ES), "cgcom");

        assertThat(message.getSubject()).isEqualTo("Nuevo dispositivo en tu wallet");
        assertThat(htmlOf(message))
                .contains("El 30/10/2026 a las 10:42 se registró el dispositivo «Windows · Edge» en tu wallet.")
                .contains("Si has sido tú, no tienes que hacer nada. Si no, revócalo.")
                .contains("href=\"" + DEVICES + "\"")
                .doesNotContain("Para entrar se añadió una passkey nueva");
    }

    @Test
    void sendNewDeviceNotice_passkeyAddedInTheSession_saysSoInTheSameEmail() throws Exception {
        // EUD-8 FR-10: one email, the new-device one with the passkey line
        when(tenantRegistryRepository.findDisplayName("cgcom")).thenReturn(Mono.just("CGCOM"));

        MimeMessage message = capture(sender.sendNewDeviceNotice(TO,
                new NewDeviceNotice(AT, "Windows · Edge", true, DEVICES), CA), "cgcom");

        assertThat(message.getSubject()).isEqualTo("Nou dispositiu al teu wallet");
        assertThat(htmlOf(message))
                .contains("es va registrar el dispositiu «Windows · Edge» al teu wallet.")
                .contains("Per entrar es va afegir una passkey nova al teu compte.")
                .contains("Si no, revoca&#39;l.")
                .contains("Revisar els meus dispositius");
    }

    // --- Cuenta nueva (alta con ticket) ---

    @Test
    void sendAccountCreatedNotice_holder_getsTheDateTheDeviceAndTheLinkWithoutTheSystem() throws Exception {
        // FR-29 and EUD-15 AC-09: the new-account email carries the name of the device
        when(tenantRegistryRepository.findDisplayName("cgcom")).thenReturn(Mono.just("CGCOM"));
        var notice = new AccountCreatedNotice(AT, "https://cgcom.eudistack.net/not-me#tok",
                Instant.parse("2026-11-06T09:42:00Z"), true, "iPhone · Safari");

        MimeMessage message = capture(sender.sendAccountCreatedNotice("ana@cgcom.es", notice, ES), "cgcom");

        assertThat(message.getSubject()).isEqualTo("Se ha creado tu wallet de CGCOM");
        assertThat(htmlOf(message))
                .contains("El 30/10/2026 a las 10:42 se creó tu wallet, en el dispositivo «iPhone · Safari».")
                .contains("No he sido yo")
                .contains("href=\"https://cgcom.eudistack.net/not-me#tok\"")
                .contains("El enlace caduca el 06/11/2026.");
    }

    @Test
    void sendAccountCreatedNotice_accountThatAlreadyExisted_saysAPasskeyWasAdded() throws Exception {
        // EC-01, P17 (provisional texts)
        when(tenantRegistryRepository.findDisplayName("cgcom")).thenReturn(Mono.just("CGCOM"));
        var notice = new AccountCreatedNotice(AT, "https://cgcom.eudistack.net/not-me#tok",
                Instant.parse("2026-11-06T09:42:00Z"), false, "iPhone · Safari");

        MimeMessage message = capture(sender.sendAccountCreatedNotice("ana@cgcom.es", notice, Locale.ENGLISH),
                "cgcom");

        assertThat(message.getSubject()).isEqualTo("A passkey has been added to your CGCOM wallet");
        assertThat(htmlOf(message))
                .contains("On 30/10/2026 at 10:42 a passkey was added to your wallet, on the device")
                .doesNotContain("your wallet was created");
    }

    // --- Alerta al contacto de seguridad ---

    @Test
    void sendOnboardingAlert_securityContact_getsTheMaskedEmailAndTheDateWithoutTheSystem() throws Exception {
        // FR-32: the alert never carries the holder's full email
        when(tenantRegistryRepository.findDisplayName("cgcom")).thenReturn(Mono.just("CGCOM"));
        var alert = new OnboardingAlert(OnboardingAlert.mask("ana.garcia@cgcom.es"), AT, true);

        MimeMessage message = capture(sender.sendOnboardingAlert("security@cgcom.es", alert, ES), "cgcom");

        assertThat(message.getSubject()).isEqualTo("Alta de wallet no reconocida");
        assertThat(message.getAllRecipients()).extracting(Address::toString).containsExactly("security@cgcom.es");
        assertThat(htmlOf(message))
                .contains("El titular de a***@cgcom.es ha indicado que no creó su wallet.")
                .contains("Alta: 30/10/2026 10:42")
                .contains("revocado los dispositivos de esa alta")
                .doesNotContain("ana.garcia");
    }

    @Test
    void sendOnboardingAlert_accountThatAlreadyExisted_saysAPasskeyWasAdded() throws Exception {
        when(tenantRegistryRepository.findDisplayName("cgcom")).thenReturn(Mono.just("CGCOM"));
        var alert = new OnboardingAlert(OnboardingAlert.mask("ana.garcia@cgcom.es"), AT, false);

        MimeMessage message = capture(sender.sendOnboardingAlert("security@cgcom.es", alert, Locale.ENGLISH),
                "cgcom");

        assertThat(message.getSubject()).isEqualTo("Wallet passkey not recognized");
        assertThat(htmlOf(message))
                .contains("The holder of a***@cgcom.es has said they did not add the new passkey to their wallet.")
                .contains("Added: 30/10/2026 10:42")
                .doesNotContain("ana.garcia");
    }

    // --- External system access trace ---

    @Test
    void sendOtp_smtpRejectsTheMessage_propagatesTheError() {
        when(tenantRegistryRepository.findDisplayName("dome")).thenReturn(Mono.just("DOME"));
        doThrow(new MailSendException("relay denied")).when(mailSender).send(any(MimeMessage.class));

        StepVerifier.create(sender.sendOtp(TO, "123456", ES)
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, "dome")))
                .expectError(MailSendException.class)
                .verify();
    }

    @Test
    void sendOtp_smtpAccepts_stagesASuccessfulExternalSystemAccessWithoutTheRecipientOrTheCode() {
        when(tenantRegistryRepository.findDisplayName("dome")).thenReturn(Mono.just("DOME"));

        send("dome", ES);

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

        StepVerifier.create(sender.sendOtp(TO, "123456", ES)
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, "dome")))
                .expectError(MailSendException.class)
                .verify();

        AuditEntry entry = auditTrail.staged().getFirst();
        assertThat(entry.result()).isEqualTo(AuditResult.FAILURE);
        assertThat(entry.reason()).isEqualTo("ErrorResponse");
    }

    @Test
    void sendNewDeviceNotice_smtpAccepts_stagesTheAccessAsTheNewDeviceEmailWithoutTheRecipient() {
        when(tenantRegistryRepository.findDisplayName("dome")).thenReturn(Mono.just("DOME"));

        StepVerifier.create(sender.sendNewDeviceNotice(TO, new NewDeviceNotice(AT, "Mac · Chrome", false, DEVICES), ES)
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, "dome")))
                .verifyComplete();

        AuditEntry entry = auditTrail.staged().getFirst();
        assertThat(entry.result()).isEqualTo(AuditResult.SUCCESS);
        assertThat(entry.details()).containsEntry("operation", "new-device-email");
        assertThat(entry.toString()).doesNotContain(TO);
    }

    private MimeMessage send(String tenant, Locale locale) {
        return capture(sender.sendOtp(TO, "123456", locale), tenant);
    }

    private MimeMessage capture(Mono<Void> sending, String tenant) {
        StepVerifier.create(sending.contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, tenant)))
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
