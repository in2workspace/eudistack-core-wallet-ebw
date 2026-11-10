package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.OnboardingPreregistration;
import com.eudistack.ebw.domain.model.RegistrationTicket;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.model.exception.InvalidTicketException;
import com.eudistack.ebw.domain.repository.OnboardingPreregistrationRepository;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.RegistrationTicketService;
import com.eudistack.ebw.domain.service.RegistrationTicketService.IssuedTicket;
import com.eudistack.ebw.domain.spi.HashProvider;
import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link RedeemOnboardingTicketWorkflow} (AC-06, AC-08, AC-09, EC-01, EC-02, EC-03, EC-05). */
@ExtendWith(MockitoExtension.class)
class RedeemOnboardingTicketWorkflowTest {

    private static final String TICKET = "Zk3q9Xw2Lp7Rt4Vb8Nc1Ha";
    private static final String HASH = "h".repeat(64);
    private static final String EMAIL = "ana@example.com";
    private static final String OFFER = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fi.example%2Fo";

    @Mock private OnboardingPreregistrationRepository preregistrationRepository;
    @Mock private WalletUserRepository userRepository;
    @Mock private UserPasskeyRepository passkeyRepository;
    @Mock private RegistrationTicketService ticketService;
    @Mock private HashProvider hashProvider;
    @Mock private SecureRandomGenerator randomGenerator;
    @Mock private AuditService auditService;

    private RedeemOnboardingTicketWorkflow workflow;
    private OnboardingPreregistration preregistration;
    private WalletUser account;
    private Instant ticketExpiry;

    @BeforeEach
    void setUp() {
        workflow = new RedeemOnboardingTicketWorkflow(preregistrationRepository, userRepository, passkeyRepository,
                ticketService, hashProvider, randomGenerator, auditService);
        preregistration = OnboardingPreregistration.create(HASH, EMAIL, OFFER, "portal-machine.example.org",
                Duration.ofMinutes(5));
        account = WalletUser.create(EMAIL, new byte[WalletUser.USER_HANDLE_LENGTH]);
        ticketExpiry = Instant.now().plus(RegistrationTicket.TTL);
        lenient().when(hashProvider.sha256(TICKET)).thenReturn(HASH);
        lenient().when(preregistrationRepository.redeem(HASH)).thenReturn(Mono.just(preregistration));
        lenient().when(preregistrationRepository.deleteById(any())).thenReturn(Mono.just(true));
        lenient().when(preregistrationRepository.keepUntil(any(), any())).thenReturn(Mono.empty());
        lenient().when(preregistrationRepository.assignUserHandle(any(), any())).thenReturn(Mono.empty());
        lenient().when(ticketService.issueForPreregistration(any(), any()))
                .thenReturn(Mono.just(new IssuedTicket("rt_raw", ticketExpiry)));
        lenient().when(randomGenerator.generateBytes(WalletUser.USER_HANDLE_LENGTH))
                .thenReturn(new byte[WalletUser.USER_HANDLE_LENGTH]);
        lenient().when(auditService.record(anyString(), any(), anyString(), any(), any())).thenReturn(Mono.empty());
    }

    @Test
    void redeem_emailWithoutAccount_givesRegistrationTicketWithoutCreatingTheAccount() {
        // Arrange
        when(userRepository.findAllByEmailIgnoreCase(EMAIL)).thenReturn(Flux.empty());

        // Act + Assert
        StepVerifier.create(workflow.redeem(TICKET, null))
                .assertNext(redemption -> {
                    assertThat(redemption.hasPasskeys()).isFalse();
                    assertThat(redemption.sessionOfAccount()).isFalse();
                    assertThat(redemption.registrationTicket()).isEqualTo("rt_raw");
                    assertThat(redemption.expiresIn()).isBetween(299L, 300L);
                    assertThat(redemption.credentialOffer()).isEqualTo(OFFER);
                })
                .verifyComplete();
        verify(preregistrationRepository).assignUserHandle(eq(preregistration.id()), any());
        verify(ticketService).issueForPreregistration(isNull(), eq(preregistration.id()));
        verify(userRepository, never()).save(any());
        verify(preregistrationRepository, never()).deleteById(any());
    }

    @Test
    void redeem_registration_keepsThePreregistrationUntilTheRegistrationTicketExpires() {
        // Arrange: decision P8, the pre-registration must outlive its registration ticket
        when(userRepository.findAllByEmailIgnoreCase(EMAIL)).thenReturn(Flux.empty());

        // Act
        StepVerifier.create(workflow.redeem(TICKET, null)).expectNextCount(1).verifyComplete();

        // Assert
        verify(preregistrationRepository).keepUntil(preregistration.id(), ticketExpiry);
    }

    @Test
    void redeem_accountWithoutPasskeys_givesRegistrationTicketBoundToTheAccount() {
        // Arrange: EC-01, an email sign-up abandoned before the passkey
        when(userRepository.findAllByEmailIgnoreCase(EMAIL)).thenReturn(Flux.just(account));
        when(passkeyRepository.countByUserId(account.getId())).thenReturn(Mono.just(0L));

        // Act + Assert
        StepVerifier.create(workflow.redeem(TICKET, null))
                .assertNext(redemption -> assertThat(redemption.registrationTicket()).isEqualTo("rt_raw"))
                .verifyComplete();
        verify(ticketService).issueForPreregistration(account.getId(), preregistration.id());
        verify(preregistrationRepository, never()).assignUserHandle(any(), any());
    }

    @Test
    void redeem_emailThatDiffersOnlyInCase_findsTheAccountIgnoringCase() {
        // Arrange: EC-15, P16 - the ticket says Ana@Example.com and the account ana@example.com
        var mixedCase = OnboardingPreregistration.create(HASH, "Ana@Example.com", OFFER, "portal-machine.example.org",
                Duration.ofMinutes(5));
        when(preregistrationRepository.redeem(HASH)).thenReturn(Mono.just(mixedCase));
        when(userRepository.findAllByEmailIgnoreCase("Ana@Example.com")).thenReturn(Flux.just(account));
        when(passkeyRepository.countByUserId(account.getId())).thenReturn(Mono.just(1L));

        // Act + Assert: the account is the one of the email, with passkeys, and no other is created
        StepVerifier.create(workflow.redeem(TICKET, null))
                .assertNext(redemption -> assertThat(redemption.hasPasskeys()).isTrue())
                .verifyComplete();
        verify(userRepository, never()).save(any());
        verify(preregistrationRepository, never()).assignUserHandle(any(), any());
    }

    @Test
    void redeem_twoAccountsThatDifferOnlyInCase_isInvalidTicketAndDeletesThePreregistration() {
        // Arrange: EC-15, P16 - the account cannot be told: it counts as an existing one
        var other = WalletUser.create("ANA@example.com", new byte[WalletUser.USER_HANDLE_LENGTH]);
        when(userRepository.findAllByEmailIgnoreCase(EMAIL)).thenReturn(Flux.just(account, other));

        // Act + Assert
        StepVerifier.create(workflow.redeem(TICKET, null)).expectError(InvalidTicketException.class).verify();
        verify(preregistrationRepository).deleteById(preregistration.id());
        verify(ticketService, never()).issueForPreregistration(any(), any());
        verify(auditService).record("onboarding_preregistration", preregistration.id(),
                AuthAuditEvents.ONBOARDING_TICKET_REJECTED, null, Map.of("reason", "ambiguous_account"));
    }

    @Test
    void redeem_accountWithPasskeys_givesNoRegistrationTicketAndDeletesThePreregistration() {
        // Arrange: AC-08, FR-28
        when(userRepository.findAllByEmailIgnoreCase(EMAIL)).thenReturn(Flux.just(account));
        when(passkeyRepository.countByUserId(account.getId())).thenReturn(Mono.just(1L));

        // Act + Assert
        StepVerifier.create(workflow.redeem(TICKET, null))
                .assertNext(redemption -> {
                    assertThat(redemption.hasPasskeys()).isTrue();
                    assertThat(redemption.sessionOfAccount()).isFalse();
                    assertThat(redemption.registrationTicket()).isNull();
                    assertThat(redemption.expiresIn()).isNull();
                    assertThat(redemption.credentialOffer()).isEqualTo(OFFER);
                })
                .verifyComplete();
        verify(preregistrationRepository).deleteById(preregistration.id());
        verify(ticketService, never()).issueForPreregistration(any(), any());
    }

    @Test
    void redeem_activeSessionOfTheAccount_saysSoAndDeletesThePreregistration() {
        // Arrange: AC-09
        when(userRepository.findAllByEmailIgnoreCase(EMAIL)).thenReturn(Flux.just(account));

        // Act + Assert
        StepVerifier.create(workflow.redeem(TICKET, account.getId()))
                .assertNext(redemption -> {
                    assertThat(redemption.sessionOfAccount()).isTrue();
                    assertThat(redemption.registrationTicket()).isNull();
                    assertThat(redemption.credentialOffer()).isEqualTo(OFFER);
                })
                .verifyComplete();
        verify(preregistrationRepository).deleteById(preregistration.id());
    }

    @Test
    void redeem_sessionOfAnotherAccount_isIgnored() {
        // Arrange: EC-02
        when(userRepository.findAllByEmailIgnoreCase(EMAIL)).thenReturn(Flux.empty());

        // Act + Assert
        StepVerifier.create(workflow.redeem(TICKET, UUID.randomUUID()))
                .assertNext(redemption -> {
                    assertThat(redemption.sessionOfAccount()).isFalse();
                    assertThat(redemption.registrationTicket()).isEqualTo("rt_raw");
                })
                .verifyComplete();
    }

    @Test
    void redeem_withoutOffer_answersWithoutIt() {
        // Arrange: EC-05
        var withoutOffer = OnboardingPreregistration.create(HASH, EMAIL, null, "portal-machine.example.org",
                Duration.ofMinutes(5));
        when(preregistrationRepository.redeem(HASH)).thenReturn(Mono.just(withoutOffer));
        when(userRepository.findAllByEmailIgnoreCase(EMAIL)).thenReturn(Flux.empty());

        // Act + Assert
        StepVerifier.create(workflow.redeem(TICKET, null))
                .assertNext(redemption -> assertThat(redemption.credentialOffer()).isNull())
                .verifyComplete();
    }

    @Test
    void redeem_unknownUsedOrExpiredTicket_isInvalidTicketAndTracedWithoutTheTicket() {
        // Arrange: AC-06, AC-12
        when(preregistrationRepository.redeem(HASH)).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(workflow.redeem(TICKET, null)).expectError(InvalidTicketException.class).verify();
        verify(auditService).record(eq("onboarding_preregistration"), any(),
                eq(AuthAuditEvents.ONBOARDING_TICKET_REJECTED), isNull(), eq(Map.of()));
        verify(userRepository, never()).findAllByEmailIgnoreCase(anyString());
    }

    @Test
    void redeem_trace_carriesTheOutcomeAndTheSystemButNeverTheEmail() {
        // Arrange: AC-19
        when(userRepository.findAllByEmailIgnoreCase(EMAIL)).thenReturn(Flux.empty());
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> details = ArgumentCaptor.forClass(Map.class);

        // Act
        StepVerifier.create(workflow.redeem(TICKET, null)).expectNextCount(1).verifyComplete();

        // Assert
        verify(auditService).record(eq("onboarding_preregistration"), eq(preregistration.id()),
                eq(AuthAuditEvents.ONBOARDING_TICKET_REDEEMED), isNull(), details.capture());
        assertThat(details.getValue()).containsEntry("outcome", "registration")
                .containsEntry("requested_by", "portal-machine.example.org");
        assertThat(details.getValue().values()).doesNotContain(EMAIL, TICKET, "rt_raw");
    }
}
