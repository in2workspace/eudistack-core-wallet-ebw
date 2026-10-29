package com.eudistack.ebw.infrastructure.adapter.email;

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
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class SmtpEmailSender implements EmailSender {

    private static final String OTP_TEMPLATE = "verification-code-email";
    private static final String OTP_SUBJECT_KEY = "email.tx-code.subject";
    private static final String NEW_PASSKEY_TEMPLATE = "new-passkey-email";
    private static final String NEW_PASSKEY_SUBJECT_KEY = "email.new-passkey.subject";
    private static final String UNKNOWN_MAIL_PROVIDER = "unknown";
    /** The only message bundle is English. */
    private static final Locale LOCALE = Locale.ENGLISH;
    private static final String ICONS_PATH = "email/icons/";
    private static final Map<String, byte[]> ICONS = new ConcurrentHashMap<>();

    private final JavaMailSender mailSender;
    private final SpringTemplateEngine templateEngine;
    private final MessageSource messageSource;
    private final TenantConfigService tenantConfigService;
    private final TenantRegistryRepository tenantRegistryRepository;
    private final EmailBrandingResolver emailBrandingResolver;
    private final ExternalSystemAccessRecorder externalSystemAccessRecorder;
    private final long expirationMinutes;
    private final String defaultMailFrom;

    public SmtpEmailSender(JavaMailSender mailSender,
                           SpringTemplateEngine templateEngine,
                           MessageSource messageSource,
                           TenantConfigService tenantConfigService,
                           TenantRegistryRepository tenantRegistryRepository,
                           EmailBrandingResolver emailBrandingResolver,
                           ExternalSystemAccessRecorder externalSystemAccessRecorder,
                           OtpProperties otpProperties,
                           @Value("${spring.mail.properties.mail.smtp.from:noreply@eudistack.com}") String defaultMailFrom) {
        this.mailSender = mailSender;
        this.templateEngine = templateEngine;
        this.messageSource = messageSource;
        this.tenantConfigService = tenantConfigService;
        this.tenantRegistryRepository = tenantRegistryRepository;
        this.emailBrandingResolver = emailBrandingResolver;
        this.externalSystemAccessRecorder = externalSystemAccessRecorder;
        this.expirationMinutes = otpProperties.expiration().toMinutes();
        this.defaultMailFrom = defaultMailFrom;
    }

    @Override
    public Mono<Void> sendOtp(String email, String code) {
        return sendBranded(email, OTP_TEMPLATE, OTP_SUBJECT_KEY, Map.of(
                "txCode", code,
                "expirationMinutes", expirationMinutes));
    }

    @Override
    public Mono<Void> sendNewPasskeyNotice(String email) {
        return sendBranded(email, NEW_PASSKEY_TEMPLATE, NEW_PASSKEY_SUBJECT_KEY, Map.of());
    }

    /** Resolves the tenant's sender, display name and branding from the request context, then sends. */
    private Mono<Void> sendBranded(String email, String template, String subjectKey, Map<String, Object> variables) {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, "");
            Mono<String> displayName = tenant.isBlank()
                    ? Mono.just(tenant)
                    : tenantRegistryRepository.findDisplayName(tenant)
                            .filter(name -> !name.isBlank())
                            .defaultIfEmpty(tenant);
            return Mono.zip(tenantConfigService.getStringOrDefault("ebw.mail_from", defaultMailFrom), displayName)
                    .flatMap(tuple -> Mono.fromCallable(
                                    () -> buildMessage(email, template, subjectKey, variables, tuple.getT1(), tuple.getT2(),
                                            emailBrandingResolver.resolve(tenant)))
                            .subscribeOn(Schedulers.boundedElastic()))
                    .flatMap(mimeMessage -> externalSystemAccessRecorder.recordAccess(mailProvider(), template,
                            Mono.<Void>fromRunnable(() -> mailSender.send(mimeMessage))
                                    .subscribeOn(Schedulers.boundedElastic())));
        }).then();
    }

    private MimeMessage buildMessage(String email, String template, String subjectKey, Map<String, Object> variables,
                                     String from, String tenantDisplayName, EmailBranding branding)
            throws MessagingException {
        var context = new Context(LOCALE);
        variables.forEach(context::setVariable);
        context.setVariable("branding", branding);
        context.setVariable("tenantDisplayName", tenantDisplayName);

        var html = templateEngine.process(template, context);
        // The subject may carry an admin-configured value (tenant display name).
        var subject = messageSource.getMessage(subjectKey, new Object[]{tenantDisplayName}, LOCALE)
                .replaceAll("[\\r\\n]+", " ");

        var mimeMessage = mailSender.createMimeMessage();
        var helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");
        helper.setFrom(from);
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
