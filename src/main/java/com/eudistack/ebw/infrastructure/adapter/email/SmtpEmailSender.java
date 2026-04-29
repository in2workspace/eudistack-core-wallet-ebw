package com.eudistack.ebw.infrastructure.adapter.email;

import com.eudistack.ebw.domain.service.TenantConfigService;
import com.eudistack.ebw.domain.spi.EmailSender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.Locale;

@Component
public class SmtpEmailSender implements EmailSender {

    private static final Logger log = LoggerFactory.getLogger(SmtpEmailSender.class);

    private final JavaMailSender mailSender;
    private final SpringTemplateEngine templateEngine;
    private final MessageSource messageSource;
    private final TenantConfigService tenantConfigService;
    private final String defaultMailFrom;

    public SmtpEmailSender(JavaMailSender mailSender,
                           SpringTemplateEngine templateEngine,
                           MessageSource messageSource,
                           TenantConfigService tenantConfigService,
                           @Value("${spring.mail.properties.mail.smtp.from:noreply@eudistack.com}") String defaultMailFrom) {
        this.mailSender = mailSender;
        this.templateEngine = templateEngine;
        this.messageSource = messageSource;
        this.tenantConfigService = tenantConfigService;
        this.defaultMailFrom = defaultMailFrom;
    }

    @Override
    public Mono<Void> sendOtp(String email, String code) {
        return tenantConfigService.getStringOrDefault("ebw.mail_from", defaultMailFrom)
                .flatMap(from -> Mono.fromCallable(() -> {
                    var context = new Context(Locale.getDefault());
                    context.setVariable("txCode", code);

                    var html = templateEngine.process("verification-code-email", context);
                    var subject = messageSource.getMessage("email.tx-code.subject", null, Locale.getDefault());

                    var mimeMessage = mailSender.createMimeMessage();
                    var helper = new MimeMessageHelper(mimeMessage, "UTF-8");
                    helper.setFrom(from);
                    helper.setTo(email);
                    helper.setSubject(subject);
                    helper.setText(html, true);
                    mailSender.send(mimeMessage);
                    return null;
                }).subscribeOn(Schedulers.boundedElastic()))
                .then();
    }
}
