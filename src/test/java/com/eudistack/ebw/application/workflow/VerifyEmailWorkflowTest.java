package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.AuthTokenPair;
import com.eudistack.ebw.domain.model.EmailVerification;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.model.exception.InvalidOtpException;
import com.eudistack.ebw.domain.model.exception.RateLimitExceededException;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.AuthTokenService;
import com.eudistack.ebw.domain.service.OtpService;
import com.eudistack.ebw.domain.spi.EmailRateLimiter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class VerifyEmailWorkflowTest {

    private static final String EMAIL = "user@example.com";
    private static final String CODE = "123456";

    private OtpService otpService;
    private AuthTokenService authTokenService;
    private WalletUserRepository userRepository;
    private AuditService auditService;
    private EmailRateLimiter emailRateLimiter;
    private VerifyEmailWorkflow workflow;

    @BeforeEach
    void setUp() {
        otpService = mock(OtpService.class);
        authTokenService = mock(AuthTokenService.class);
        userRepository = mock(WalletUserRepository.class);
        auditService = mock(AuditService.class);
        emailRateLimiter = mock(EmailRateLimiter.class);
        workflow = new VerifyEmailWorkflow(otpService, authTokenService, userRepository,
                auditService, emailRateLimiter);
    }

    @Test
    void verifyEmail_validCode_resetsTheRateLimitCountersForThatEmail() {
        var user = givenAnExistingUser();
        givenTheOtpIsAccepted();
        givenTokensAreIssuedFor(user);
        when(emailRateLimiter.resetForEmail(EMAIL)).thenReturn(Mono.empty());

        StepVerifier.create(workflow.verifyEmail(EMAIL, CODE))
                .expectNextCount(1)
                .verifyComplete();

        verify(emailRateLimiter).resetForEmail(EMAIL);
    }

    @Test
    void verifyEmail_firstTimeUser_createsTheAccountAndStillResetsTheCounters() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Mono.empty());
        when(userRepository.save(any(WalletUser.class)))
                .thenAnswer(invocation -> Mono.just(invocation.getArgument(0)));
        givenTheOtpIsAccepted();
        when(authTokenService.issueTokenPair(any(WalletUser.class), isNull()))
                .thenReturn(Mono.just(new AuthTokenPair("access", "refresh", 900)));
        when(auditService.record(eq("user"), any(), eq("USER_AUTHENTICATED"), any(), any(Map.class)))
                .thenReturn(Mono.empty());
        when(emailRateLimiter.resetForEmail(EMAIL)).thenReturn(Mono.empty());

        StepVerifier.create(workflow.verifyEmail(EMAIL, CODE))
                .expectNextCount(1)
                .verifyComplete();

        verify(userRepository).save(any(WalletUser.class));
        verify(emailRateLimiter).resetForEmail(EMAIL);
    }

    @Test
    void verifyEmail_invalidCode_neverResetsTheCounters() {
        givenAnExistingUser();
        when(emailRateLimiter.checkVerifyRate(EMAIL)).thenReturn(Mono.empty());
        when(otpService.verify(EMAIL, CODE)).thenReturn(Mono.error(new InvalidOtpException()));

        StepVerifier.create(workflow.verifyEmail(EMAIL, CODE))
                .expectError(InvalidOtpException.class)
                .verify();

        verify(emailRateLimiter, never()).resetForEmail(any());
    }

    @Test
    void verifyEmail_verifyRateExceeded_issuesNoTokensAndNeverResetsTheCounters() {
        givenAnExistingUser();
        when(otpService.verify(EMAIL, CODE)).thenReturn(Mono.just(
                EmailVerification.create(EMAIL, "hash", Instant.now().plusSeconds(600))));
        when(emailRateLimiter.checkVerifyRate(EMAIL))
                .thenReturn(Mono.error(new RateLimitExceededException(3600)));

        StepVerifier.create(workflow.verifyEmail(EMAIL, CODE))
                .expectError(RateLimitExceededException.class)
                .verify();

        verify(authTokenService, never()).issueTokenPair(any(), any());
        verify(emailRateLimiter, never()).resetForEmail(any());
    }

    private WalletUser givenAnExistingUser() {
        var user = WalletUser.create(EMAIL);
        when(userRepository.findByEmail(EMAIL)).thenReturn(Mono.just(user));
        return user;
    }

    private void givenTheOtpIsAccepted() {
        when(emailRateLimiter.checkVerifyRate(EMAIL)).thenReturn(Mono.empty());
        when(otpService.verify(EMAIL, CODE)).thenReturn(Mono.just(
                EmailVerification.create(EMAIL, "hash", Instant.now().plusSeconds(600))));
    }

    private void givenTokensAreIssuedFor(WalletUser user) {
        when(authTokenService.issueTokenPair(user, null))
                .thenReturn(Mono.just(new AuthTokenPair("access", "refresh", 900)));
        when(auditService.record(eq("user"), eq(user.getId()), eq("USER_AUTHENTICATED"),
                eq(user.getId()), any(Map.class))).thenReturn(Mono.empty());
    }
}
