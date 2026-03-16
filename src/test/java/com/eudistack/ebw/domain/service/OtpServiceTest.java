package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.EmailVerification;
import com.eudistack.ebw.domain.model.exception.InvalidOtpException;
import com.eudistack.ebw.domain.model.exception.OtpExpiredException;
import com.eudistack.ebw.domain.model.exception.TooManyAttemptsException;
import com.eudistack.ebw.domain.repository.EmailVerificationRepository;
import com.eudistack.ebw.domain.spi.EmailSender;
import com.eudistack.ebw.domain.spi.HashProvider;
import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class OtpServiceTest {

    private EmailVerificationRepository verificationRepository;
    private HashProvider hashProvider;
    private SecureRandomGenerator randomGenerator;
    private EmailSender emailSender;
    private OtpService otpService;

    @BeforeEach
    void setUp() {
        verificationRepository = mock(EmailVerificationRepository.class);
        hashProvider = mock(HashProvider.class);
        randomGenerator = mock(SecureRandomGenerator.class);
        emailSender = mock(EmailSender.class);
        otpService = new OtpService(verificationRepository, hashProvider, randomGenerator,
                emailSender, 6, Duration.ofMinutes(10), 5);
    }

    @Test
    void generateAndSend_validEmail_generatesOtpAndSendsEmail() {
        // Arrange
        var email = "user@example.com";
        when(randomGenerator.generateOtp(6)).thenReturn("482916");
        when(hashProvider.hash("482916")).thenReturn(Mono.just("bcrypt-hash"));
        when(verificationRepository.invalidateByEmail(email)).thenReturn(Mono.empty());
        when(verificationRepository.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        when(emailSender.sendOtp(email, "482916")).thenReturn(Mono.empty());

        // Act
        var result = otpService.generateAndSend(email);

        // Assert
        StepVerifier.create(result)
                .verifyComplete();

        verify(verificationRepository).invalidateByEmail(email);
        verify(emailSender).sendOtp(email, "482916");

        var captor = ArgumentCaptor.forClass(EmailVerification.class);
        verify(verificationRepository).save(captor.capture());
        assertThat(captor.getValue().getUserEmail()).isEqualTo(email);
        assertThat(captor.getValue().getCodeHash()).isEqualTo("bcrypt-hash");
        assertThat(captor.getValue().isUsed()).isFalse();
    }

    @Test
    void verify_validCode_returnsVerificationAndMarksUsed() {
        // Arrange
        var email = "user@example.com";
        var verification = EmailVerification.create(email, "bcrypt-hash", Instant.now().plusSeconds(600));
        when(verificationRepository.findActiveByEmail(email)).thenReturn(Mono.just(verification));
        when(hashProvider.verify("482916", "bcrypt-hash")).thenReturn(Mono.just(true));
        when(verificationRepository.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Act
        var result = otpService.verify(email, "482916");

        // Assert
        StepVerifier.create(result)
                .assertNext(v -> {
                    assertThat(v.getUserEmail()).isEqualTo(email);
                    assertThat(v.isUsed()).isTrue();
                })
                .verifyComplete();
    }

    @Test
    void verify_wrongCode_throwsInvalidOtpException() {
        // Arrange
        var email = "user@example.com";
        var verification = EmailVerification.create(email, "bcrypt-hash", Instant.now().plusSeconds(600));
        when(verificationRepository.findActiveByEmail(email)).thenReturn(Mono.just(verification));
        when(hashProvider.verify("000000", "bcrypt-hash")).thenReturn(Mono.just(false));
        when(verificationRepository.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Act
        var result = otpService.verify(email, "000000");

        // Assert
        StepVerifier.create(result)
                .expectError(InvalidOtpException.class)
                .verify();
        assertThat(verification.getAttempts()).isEqualTo(1);
    }

    @Test
    void verify_expiredCode_throwsOtpExpiredException() {
        // Arrange
        var email = "user@example.com";
        var verification = EmailVerification.create(email, "bcrypt-hash", Instant.now().minusSeconds(1));
        when(verificationRepository.findActiveByEmail(email)).thenReturn(Mono.just(verification));

        // Act
        var result = otpService.verify(email, "482916");

        // Assert
        StepVerifier.create(result)
                .expectError(OtpExpiredException.class)
                .verify();
    }

    @Test
    void verify_maxAttemptsReached_throwsTooManyAttemptsException() {
        // Arrange
        var email = "user@example.com";
        var verification = new EmailVerification(
                java.util.UUID.randomUUID(), email, "bcrypt-hash", 5,
                Instant.now().plusSeconds(600), false, Instant.now());
        when(verificationRepository.findActiveByEmail(email)).thenReturn(Mono.just(verification));

        // Act
        var result = otpService.verify(email, "482916");

        // Assert
        StepVerifier.create(result)
                .expectError(TooManyAttemptsException.class)
                .verify();
    }

    @Test
    void verify_noActiveVerification_throwsInvalidOtpException() {
        // Arrange
        var email = "user@example.com";
        when(verificationRepository.findActiveByEmail(email)).thenReturn(Mono.empty());

        // Act
        var result = otpService.verify(email, "482916");

        // Assert
        StepVerifier.create(result)
                .expectError(InvalidOtpException.class)
                .verify();
    }

    @Test
    void verify_wrongCodeReachesMaxAttempts_throwsTooManyAttemptsException() {
        // Arrange
        var email = "user@example.com";
        var verification = new EmailVerification(
                java.util.UUID.randomUUID(), email, "bcrypt-hash", 4,
                Instant.now().plusSeconds(600), false, Instant.now());
        when(verificationRepository.findActiveByEmail(email)).thenReturn(Mono.just(verification));
        when(hashProvider.verify("000000", "bcrypt-hash")).thenReturn(Mono.just(false));
        when(verificationRepository.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Act
        var result = otpService.verify(email, "000000");

        // Assert
        StepVerifier.create(result)
                .expectError(TooManyAttemptsException.class)
                .verify();
        assertThat(verification.getAttempts()).isEqualTo(5);
    }
}
