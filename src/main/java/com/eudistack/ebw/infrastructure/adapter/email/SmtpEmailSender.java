package com.eudistack.ebw.infrastructure.adapter.email;

import com.eudistack.ebw.domain.model.AccountCompleteNotice;
import com.eudistack.ebw.domain.model.AccountCreatedNotice;
import com.eudistack.ebw.domain.model.EmailLanguage;
import com.eudistack.ebw.domain.model.NewDeviceNotice;
import com.eudistack.ebw.domain.model.NewPasskeyNotice;
import com.eudistack.ebw.domain.model.OnboardingAlert;
import com.eudistack.ebw.domain.service.EmailSettingsService;
import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.model.audit.ExternalSystemTarget;
import com.eudistack.ebw.domain.repository.TenantRegistryRepository;
import com.eudistack.ebw.domain.service.TenantConfigService;
import com.eudistack.ebw.domain.spi.EmailSender;
import com.eudistack.ebw.infrastructure.adapter.audit.ExternalSystemAccessRecorder;
import com.eudistack.ebw.infrastructure.adapter.properties.OtpProperties;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;
import org.springframework.util.MimeTypeUtils;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

@Component
public class SmtpEmailSender implements EmailSender {

    private static final String OTP_TEMPLATE = "verification-code-email";
    private static final String OTP_SUBJECT_KEY = "email.tx-code.subject";
    private static final String NEW_PASSKEY_TEMPLATE = "new-passkey-email";
    private static final String NEW_PASSKEY_SUBJECT_KEY = "email.new-passkey.subject";
    private static final String ONBOARDING_ALERT_TEMPLATE = "onboarding-alert-email";
    private static final String ONBOARDING_ALERT_SUBJECT_KEY = "email.onboarding-alert.subject";
    private static final String ONBOARDING_ALERT_ADDED_SUBJECT_KEY = "email.onboarding-alert.added.subject";
    private static final String ACCOUNT_CREATED_TEMPLATE = "account-created-email";
    private static final String ACCOUNT_CREATED_SUBJECT_KEY = "email.account-created.subject";
    private static final String ACCOUNT_CREATED_ADDED_SUBJECT_KEY = "email.account-created.added.subject";
    private static final String ACCOUNT_COMPLETE_TEMPLATE = "account-complete-email";
    private static final String ACCOUNT_COMPLETE_SUBJECT_KEY = "email.account-complete.subject";
    private static final String NEW_DEVICE_TEMPLATE = "new-device-email";
    private static final String NEW_DEVICE_SUBJECT_KEY = "email.new-device.subject";
    /** Dates and times as the wireframes show them, in the tenant's {@code ebw.timezone} (EUD-8 design §2.8). */
    private static final DateTimeFormatter EMAIL_DATE = DateTimeFormatter.ofPattern("dd/MM/yyyy");
    private static final DateTimeFormatter EMAIL_TIME = DateTimeFormatter.ofPattern("HH:mm");
    private static final String UNKNOWN_MAIL_PROVIDER = "unknown";
    /** Language of an email whose caller gives none; every caller chooses one (EUD-8 AD-10). */
    private static final Locale FALLBACK_LOCALE = Locale.of(EmailLanguage.DEFAULT);
    private static final String DATE = "date";
    private static final String TIME = "time";
    private static final String DEVICE_NAME = "deviceName";
    private static final String DEVICES_URL = "devicesUrl";
    private static final String ICONS_PATH = "email/icons/";
    private static final Map<String, byte[]> ICONS = new ConcurrentHashMap<>();

    private final JavaMailSender mailSender;
    private final SpringTemplateEngine templateEngine;
    private final MessageSource messageSource;
    private final TenantConfigService tenantConfigService;
    private final EmailSettingsService emailSettingsService;
    private final TenantRegistryRepository tenantRegistryRepository;
    private final EmailBrandingResolver emailBrandingResolver;
    private final ExternalSystemAccessRecorder externalSystemAccessRecorder;
    private final long expirationMinutes;
    private final String defaultMailFrom;

    @SuppressWarnings("java:S107")
    public SmtpEmailSender(JavaMailSender mailSender,
                           SpringTemplateEngine templateEngine,
                           MessageSource messageSource,
                           TenantConfigService tenantConfigService,
                           EmailSettingsService emailSettingsService,
                           TenantRegistryRepository tenantRegistryRepository,
                           EmailBrandingResolver emailBrandingResolver,
                           ExternalSystemAccessRecorder externalSystemAccessRecorder,
                           OtpProperties otpProperties,
                           @Value("${spring.mail.properties.mail.smtp.from:noreply@eudistack.com}") String defaultMailFrom) {
        this.mailSender = mailSender;
        this.templateEngine = templateEngine;
        this.messageSource = messageSource;
        this.tenantConfigService = tenantConfigService;
        this.emailSettingsService = emailSettingsService;
        this.tenantRegistryRepository = tenantRegistryRepository;
        this.emailBrandingResolver = emailBrandingResolver;
        this.externalSystemAccessRecorder = externalSystemAccessRecorder;
        this.expirationMinutes = otpProperties.expiration().toMinutes();
        this.defaultMailFrom = defaultMailFrom;
    }

    @Override
    public Mono<Void> sendOtp(String email, String code, Locale locale) {
        return sendBranded(email, OTP_TEMPLATE, OTP_SUBJECT_KEY, zone -> Map.of(
                "txCode", code,
                "expirationMinutes", expirationMinutes), locale);
    }

    @Override
    public Mono<Void> sendNewPasskeyNotice(String email, NewPasskeyNotice notice, Locale locale) {
        return sendBranded(email, NEW_PASSKEY_TEMPLATE, NEW_PASSKEY_SUBJECT_KEY, zone -> withOptional(Map.of(
                DATE, EMAIL_DATE.format(notice.addedAt().atZone(zone)),
                TIME, EMAIL_TIME.format(notice.addedAt().atZone(zone))), DEVICES_URL, notice.devicesUrl()), locale);
    }

    @Override
    public Mono<Void> sendOnboardingAlert(String securityContact, OnboardingAlert alert, Locale locale) {
        var subjectKey = alert.accountCreated() ? ONBOARDING_ALERT_SUBJECT_KEY : ONBOARDING_ALERT_ADDED_SUBJECT_KEY;
        return sendBranded(securityContact, ONBOARDING_ALERT_TEMPLATE, subjectKey, zone -> Map.of(
                "maskedEmail", alert.maskedEmail(),
                "registeredAt", EMAIL_DATE.format(alert.registeredAt().atZone(zone)) + " "
                        + EMAIL_TIME.format(alert.registeredAt().atZone(zone)),
                "accountCreated", alert.accountCreated()), locale);
    }

    @Override
    public Mono<Void> sendAccountCreatedNotice(String email, AccountCreatedNotice notice, Locale locale) {
        var subjectKey = notice.accountCreated() ? ACCOUNT_CREATED_SUBJECT_KEY : ACCOUNT_CREATED_ADDED_SUBJECT_KEY;
        return sendBranded(email, ACCOUNT_CREATED_TEMPLATE, subjectKey, zone -> withOptional(Map.of(
                DATE, EMAIL_DATE.format(notice.createdAt().atZone(zone)),
                TIME, EMAIL_TIME.format(notice.createdAt().atZone(zone)),
                "disavowalUrl", notice.disavowalUrl(),
                "linkExpiresAt", EMAIL_DATE.format(notice.linkExpiresAt().atZone(zone)),
                "accountCreated", notice.accountCreated()), DEVICE_NAME, notice.deviceName()), locale);
    }

    @Override
    public Mono<Void> sendAccountCompleteNotice(String email, AccountCompleteNotice notice, Locale locale) {
        return sendBranded(email, ACCOUNT_COMPLETE_TEMPLATE, ACCOUNT_COMPLETE_SUBJECT_KEY, zone -> Map.of(
                DATE, EMAIL_DATE.format(notice.createdAt().atZone(zone)),
                TIME, EMAIL_TIME.format(notice.createdAt().atZone(zone)),
                DEVICE_NAME, notice.deviceName()), locale);
    }

    @Override
    public Mono<Void> sendNewDeviceNotice(String email, NewDeviceNotice notice, Locale locale) {
        return sendBranded(email, NEW_DEVICE_TEMPLATE, NEW_DEVICE_SUBJECT_KEY, zone -> withOptional(Map.of(
                DATE, EMAIL_DATE.format(notice.registeredAt().atZone(zone)),
                TIME, EMAIL_TIME.format(notice.registeredAt().atZone(zone)),
                DEVICE_NAME, notice.deviceName(),
                "passkeyAdded", notice.passkeyAdded()), DEVICES_URL, notice.devicesUrl()), locale);
    }

    /** {@code Map.of} rejects nulls: an optional variable is only added when it has a value. */
    private static Map<String, Object> withOptional(Map<String, Object> variables, String key, Object value) {
        if (value == null) {
            return variables;
        }
        var all = new HashMap<>(variables);
        all.put(key, value);
        return all;
    }

    /**
     * Resolves the tenant's sender, display name, branding and time zone from the request context, then sends.
     * The variables are built with the tenant's zone, so every date is in {@code ebw.timezone}.
     */
    private Mono<Void> sendBranded(String email, String template, String subjectKey,
                                   Function<ZoneId, Map<String, Object>> variablesInZone, Locale locale) {
        var messageLocale = locale == null ? FALLBACK_LOCALE : locale;
        return emailSettingsService.current()
                .map(settings -> variablesInZone.apply(settings.zone()))
                .flatMap(variables -> sendBranded(email, template, subjectKey, variables, messageLocale));
    }

    private Mono<Void> sendBranded(String email, String template, String subjectKey, Map<String, Object> variables,
                                   Locale messageLocale) {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, "");
            Mono<String> displayName = tenant.isBlank()
                    ? Mono.just(tenant)
                    : tenantRegistryRepository.findDisplayName(tenant)
                            .filter(name -> !name.isBlank())
                            .defaultIfEmpty(tenant);
            return Mono.zip(tenantConfigService.getStringOrDefault("ebw.mail_from", defaultMailFrom), displayName)
                    .flatMap(tuple -> Mono.fromCallable(
                                    () -> buildMessage(email, template, subjectKey, variables,
                                            new TenantSender(tuple.getT1(), tuple.getT2(), emailBrandingResolver.resolve(tenant)),
                                            messageLocale))
                            .subscribeOn(Schedulers.boundedElastic()))
                    .flatMap(mimeMessage -> externalSystemAccessRecorder.recordAccess(mailProvider(), template,
                            Mono.<Void>fromRunnable(() -> mailSender.send(mimeMessage))
                                    .subscribeOn(Schedulers.boundedElastic())));
        }).then();
    }

    /** Who the email is sent as: the tenant's sender address, display name and branding. */
    private record TenantSender(String from, String displayName, EmailBranding branding) {}

    private MimeMessage buildMessage(String email, String template, String subjectKey, Map<String, Object> variables,
                                     TenantSender sender, Locale locale)
            throws MessagingException {
        var branding = sender.branding();
        var tenantDisplayName = sender.displayName();
        var context = new Context(locale);
        variables.forEach(context::setVariable);
        context.setVariable("branding", branding);
        context.setVariable("tenantDisplayName", tenantDisplayName);

        var html = templateEngine.process(template, context);
        // The subject may carry an admin-configured value (tenant display name).
        var subject = messageSource.getMessage(subjectKey, new Object[]{tenantDisplayName}, locale)
                .replaceAll("[\\r\\n]+", " ");

        var mimeMessage = mailSender.createMimeMessage();
        var helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");
        helper.setFrom(sender.from());
        helper.setTo(email);
        helper.setSubject(subject);
        // Inline parts must follow setText: otherwise the image becomes the first part of
        // multipart/related and clients (Outlook, Gmail) show it as the body and the HTML as an attachment.
        helper.setText(html, true);
        for (EmailBranding.SocialLink link : branding.socialLinks()) {
            helper.addInline("icon-" + link.type() + ".png",
                    new ByteArrayResource(ICONS.computeIfAbsent(link.type(), SmtpEmailSender::readIcon)),
                    MimeTypeUtils.IMAGE_PNG_VALUE);
        }
        return mimeMessage;
    }

    /** The SMTP server the sender is configured for, as the audit event names it. */
    private ExternalSystemTarget mailProvider() {
        if (mailSender instanceof JavaMailSenderImpl smtp && smtp.getHost() != null) {
            boolean authenticated = smtp.getUsername() != null && !smtp.getUsername().isBlank();
            return ExternalSystemTarget.mailProvider(smtp.getHost(),
                    authenticated ? ExternalSystemTarget.AUTHENTICATION_BASIC : ExternalSystemTarget.AUTHENTICATION_NONE);
        }
        return ExternalSystemTarget.mailProvider(UNKNOWN_MAIL_PROVIDER, ExternalSystemTarget.AUTHENTICATION_NONE);
    }

    /** Common icon shipped in {@code email/icons/}, referenced by the templates as {@code cid:icon-<name>.png}. */
    private static byte[] readIcon(String name) {
        String path = ICONS_PATH + name + ".png";
        try (InputStream in = new ClassPathResource(path).getInputStream()) {
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException("Missing email image: " + path, e);
        }
    }
}
