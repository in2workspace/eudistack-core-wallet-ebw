package com.eudistack.ebw.infrastructure.adapter.email;

import com.eudistack.ebw.domain.spi.EmailSender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

@Component
public class SmtpEmailSender implements EmailSender {

    private static final Logger log = LoggerFactory.getLogger(SmtpEmailSender.class);

    private final JavaMailSender mailSender;

    public SmtpEmailSender(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @Override
    public Mono<Void> sendOtp(String email, String code) {
        return Mono.fromCallable(() -> {
            var message = new SimpleMailMessage();
            message.setTo(email);
            message.setSubject("Your verification code");
            message.setText("Your verification code is: " + code + "\n\nThis code expires in 10 minutes.");
            mailSender.send(message);
            return null;
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }
}
