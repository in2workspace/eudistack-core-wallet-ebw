package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.application.workflow.PasskeyRegistrationWorkflow.RegisterPasskeyCommand;
import com.eudistack.ebw.domain.model.CeremonyType;
import com.eudistack.ebw.domain.model.IssuedSession;
import com.eudistack.ebw.domain.model.OnboardingDisavowal;
import com.eudistack.ebw.domain.model.OnboardingPreregistration;
import com.eudistack.ebw.domain.model.RegistrationTicket;
import com.eudistack.ebw.domain.model.RelyingPartySettings;
import com.eudistack.ebw.domain.model.VerifiedPasskeyRegistration;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.model.WebAuthnCeremony;
import com.eudistack.ebw.domain.model.exception.DuplicateAccountException;
import com.eudistack.ebw.domain.model.exception.InvalidTicketException;
import com.eudistack.ebw.domain.model.exception.PasskeyPrfUnsupportedException;
import com.eudistack.ebw.domain.repository.OnboardingDisavowalRepository;
import com.eudistack.ebw.domain.repository.OnboardingPreregistrationRepository;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.repository.WebAuthnCeremonyRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.RegistrationTicketService;
import com.eudistack.ebw.domain.service.WalletAuthSettingsService;
import com.eudistack.ebw.domain.spi.EmailSender;
import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
import com.eudistack.ebw.domain.spi.TransactionRunner;
import com.eudistack.ebw.domain.spi.WebAuthnVerifier;
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
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the onboarding path of {@link PasskeyRegistrationWorkflow}, registered by
 * {@link RegisterOnboardingPasskeyWorkflow} (EUD-315 task 6: AC-03,
 * EC-01, EC-04, EC-07, EC-11, EC-13; decisions P2, P6, P7 and P9).
 */
@ExtendWith(MockitoExtension.class)
class PasskeyRegistrationWithOnboardingTicketTest {

    private static final RelyingPartySettings RP = new RelyingPartySettings("rp.example", "Wallet",
            List.of("https://rp.example"));
    private static final String EMAIL = "ana@example.com";

    @Mock private RegistrationTicketService ticketService;
    @Mock private WalletUserRepository userRepository;
    @Mock private UserPasskeyRepository passkeyRepository;
    @Mock private WebAuthnCeremonyRepository ceremonyRepository;
    @Mock private WalletAuthSettingsService settingsService;
    @Mock private PasskeyCustodyPolicy custodyPolicy;
    @Mock private WebAuthnVerifier webAuthnVerifier;
    @Mock private SecureRandomGenerator randomGenerator;
    @Mock private SessionOpener sessionOpener;
    @Mock private EmailSender emailSender;
    @Mock private AuditService auditService;
    @Mock private TransactionRunner transactionRunner;
    @Mock private OnboardingPreregistrationRepository preregistrationRepository;
    @Mock private OnboardingDisavowalRepository disavowalRepository;
    @Mock private NotifyOnboardingAccountCreatedWorkflow onboardingNotice;

    private PasskeyRegistrationWorkflow workflow;
    private byte[] handle;
    private OnboardingPreregistration preregistration;
    private RegistrationTicket ticket;
    private WebAuthnCeremony ceremony;
    private VerifiedPasskeyRegistration verified;
    private IssuedSession session;

    @BeforeEach
    void setUp() {
        var steps = new PasskeyRegistrationSteps(passkeyRepository, ceremonyRepository, settingsService, custodyPolicy,
                webAuthnVerifier, auditService);
        var onboardingRegistration = new RegisterOnboardingPasskeyWorkflow(ticketService, userRepository,
                passkeyRepository, sessionOpener, auditService, transactionRunner, preregistrationRepository,
                disavowalRepository, onboardingNotice, steps);
        workflow = new PasskeyRegistrationWorkflow(ticketService, userRepository, passkeyRepository, ceremonyRepository,
                randomGenerator, sessionOpener, emailSender, auditService, transactionRunner, steps,
                onboardingRegistration);
        handle = new byte[WalletUser.USER_HANDLE_LENGTH];
        Arrays.fill(handle, (byte) 7);
        preregistration = withHandle(OnboardingPreregistration.create("h", EMAIL, null, "portal-machine.example.org",
                Duration.ofMinutes(5)), handle);
        ticket = RegistrationTicket.issueForPreregistration(null, preregistration.id(), "rt-hash", RegistrationTicket.TTL);
        ceremony = WebAuthnCeremony.startRegistration(new byte[32], null, ticket.id());
        verified = new VerifiedPasskeyRegistration("cred-1", new byte[] {1}, null, 0, List.of("internal"), true, true,
                true, "none");
        session = new IssuedSession("access", 300, "refresh", UUID.randomUUID(), UUID.randomUUID(), Instant.now());
        lenient().when(ticketService.resolve("raw")).thenReturn(Mono.just(ticket));
        lenient().when(preregistrationRepository.findById(preregistration.id())).thenReturn(Mono.just(preregistration));
        lenient().when(preregistrationRepository.deleteById(any())).thenReturn(Mono.just(true));
        lenient().when(ceremonyRepository.consume(ceremony.id(), CeremonyType.REGISTRATION)).thenReturn(Mono.just(ceremony));
        lenient().when(ceremonyRepository.insert(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        lenient().when(settingsService.relyingParty()).thenReturn(Mono.just(RP));
        lenient().when(custodyPolicy.isPasskeyCustody()).thenReturn(Mono.just(false));
        lenient().when(randomGenerator.generateBytes(WebAuthnCeremony.CHALLENGE_LENGTH)).thenReturn(new byte[32]);
        lenient().when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());
        lenient().when(transactionRunner.inTransaction(any())).thenAnswer(inv -> inv.getArgument(0));
        lenient().when(webAuthnVerifier.verifyRegistration("{json}", ceremony.challenge(), RP)).thenReturn(verified);
        lenient().when(passkeyRepository.findByCredentialId("cred-1")).thenReturn(Mono.empty());
        lenient().when(ticketService.consume(ticket)).thenReturn(Mono.empty());
        lenient().when(passkeyRepository.insert(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        lenient().when(passkeyRepository.markOnboarding(any(), any())).thenReturn(Mono.empty());
        lenient().when(sessionOpener.open(any(), any(), eq(null), eq("registration"))).thenReturn(Mono.just(session));
        lenient().when(disavowalRepository.insert(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        lenient().when(onboardingNotice.notify(any(), any())).thenReturn(Mono.empty());
    }

    private static OnboardingPreregistration withHandle(OnboardingPreregistration p, byte[] handle) {
        return new OnboardingPreregistration(p.id(), p.tokenHash(), p.email(), p.credentialOffer(), p.requestedBy(),
                handle, p.expiresAt(), Instant.now(), p.createdAt());
    }

    private static RegisterPasskeyCommand command(UUID ceremonyId, Boolean prfSupported) {
        return new RegisterPasskeyCommand("raw", ceremonyId, "{json}", prfSupported, null, "ua", null);
    }

    // ------------------------------------------------------------------ options

    @Test
    void startRegistration_emailWithoutAccount_usesTheEmailAndUserHandleOfThePreregistration() {
        // Act + Assert: decision P2, the passkey carries the user handle the account will get
        StepVerifier.create(workflow.startRegistration("raw"))
                .assertNext(options -> {
                    assertThat(options.userHandle()).isEqualTo(handle);
                    assertThat(options.userName()).isEqualTo(EMAIL);
                    assertThat(options.excludeCredentials()).isEmpty();
                })
                .verifyComplete();
        var stored = ArgumentCaptor.forClass(WebAuthnCeremony.class);
        verify(ceremonyRepository).insert(stored.capture());
        assertThat(stored.getValue().userId()).isNull();
        assertThat(stored.getValue().registrationTicketId()).isEqualTo(ticket.id());
    }

    // ------------------------------------------------------------------ registration

    @Test
    void register_emailWithoutAccount_createsTheAccountWithTheHandleAndThePasskeyInOneTransaction() {
        // Arrange: AC-03
        when(userRepository.findAllByEmailIgnoreCase(EMAIL)).thenReturn(Flux.empty());
        when(userRepository.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Act + Assert
        StepVerifier.create(workflow.register(command(ceremony.id(), null))).expectNext(session).verifyComplete();
        var created = ArgumentCaptor.forClass(WalletUser.class);
        verify(userRepository).save(created.capture());
        assertThat(created.getValue().getEmail()).isEqualTo(EMAIL);
        assertThat(created.getValue().getWebauthnUserHandle()).isEqualTo(handle);
        verify(transactionRunner).inTransaction(any());
        verify(passkeyRepository).markOnboarding(any(), eq(preregistration.id()));
        verify(preregistrationRepository).deleteById(preregistration.id());
        verify(auditService).record("user", created.getValue().getId(), AuthAuditEvents.ACCOUNT_CREATED,
                created.getValue().getId(), Map.of("onboarding", true));
    }

    @Test
    void register_newAccount_keepsTheDisavowalRowWithoutToken() {
        // Arrange: decision P6, the token is set when the new-account email is sent
        when(userRepository.findAllByEmailIgnoreCase(EMAIL)).thenReturn(Flux.empty());
        when(userRepository.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Act
        StepVerifier.create(workflow.register(command(ceremony.id(), null))).expectNextCount(1).verifyComplete();

        // Assert
        var row = ArgumentCaptor.forClass(OnboardingDisavowal.class);
        verify(disavowalRepository).insert(row.capture());
        assertThat(row.getValue().tokenHash()).isNull();
        assertThat(row.getValue().expiresAt()).isNull();
        assertThat(row.getValue().requestedBy()).isEqualTo("portal-machine.example.org");
        assertThat(row.getValue().passkeyId()).isNotNull();
        assertThat(row.getValue().accountCreated()).isTrue();
        // Provisional (P5): the new-account email goes right after the registration
        verify(onboardingNotice).notify(row.getValue().passkeyId(), "Other device · Other browser");
    }

    @Test
    void register_withTicket_theNoticeGetsTheDeviceLabelOfTheUserAgentNotTheNameOfTheClient() {
        // Arrange: EC-16, P19 - the client name is free text: an attacker with the ticket can write it
        when(userRepository.findAllByEmailIgnoreCase(EMAIL)).thenReturn(Flux.empty());
        when(userRepository.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        var iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
                + "(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";
        var command = new RegisterPasskeyCommand("raw", ceremony.id(), "{json}", null,
                "Registrado por RRHH, haga clic aqui", iphone, null);

        // Act
        StepVerifier.create(workflow.register(command)).expectNextCount(1).verifyComplete();

        // Assert
        var row = ArgumentCaptor.forClass(OnboardingDisavowal.class);
        verify(disavowalRepository).insert(row.capture());
        verify(onboardingNotice).notify(row.getValue().passkeyId(), "iPhone · Safari");
    }

    @Test
    void register_accountWithoutPasskeys_recognizesItAndKeepsTheDisavowalRowAndEmailsTheNotice() {
        // Arrange: EC-01, the ticket names the account (an email sign-up abandoned before the passkey)
        var account = WalletUser.create(EMAIL, new byte[WalletUser.USER_HANDLE_LENGTH]);
        ticket = RegistrationTicket.issueForPreregistration(account.getId(), preregistration.id(), "rt-hash", RegistrationTicket.TTL);
        ceremony = WebAuthnCeremony.startRegistration(new byte[32], account.getId(), ticket.id());
        when(ticketService.resolve("raw")).thenReturn(Mono.just(ticket));
        when(ceremonyRepository.consume(ceremony.id(), CeremonyType.REGISTRATION)).thenReturn(Mono.just(ceremony));
        when(webAuthnVerifier.verifyRegistration("{json}", ceremony.challenge(), RP)).thenReturn(verified);
        when(ticketService.consume(ticket)).thenReturn(Mono.empty());
        when(userRepository.lockById(account.getId())).thenReturn(Mono.just(account));
        when(passkeyRepository.countByUserId(account.getId())).thenReturn(Mono.just(0L));

        // Act + Assert
        StepVerifier.create(workflow.register(command(ceremony.id(), null))).expectNext(session).verifyComplete();
        verify(userRepository, never()).save(any());
        var row = ArgumentCaptor.forClass(OnboardingDisavowal.class);
        verify(disavowalRepository).insert(row.capture());
        assertThat(row.getValue().accountCreated()).isFalse();
        assertThat(row.getValue().userId()).isEqualTo(account.getId());
        // P17: the account that already existed is warned too
        verify(onboardingNotice).notify(eq(row.getValue().passkeyId()), any());
        verify(preregistrationRepository).deleteById(preregistration.id());
    }

    @Test
    void register_accountThatGotAPasskeyAfterTheRedemption_isRejectedAndThePreregistrationDeleted() {
        // Arrange: decision P7, FR-28 - the ticket never adds a passkey to an account that has one
        var account = WalletUser.create(EMAIL, new byte[WalletUser.USER_HANDLE_LENGTH]);
        ticket = RegistrationTicket.issueForPreregistration(account.getId(), preregistration.id(), "rt-hash", RegistrationTicket.TTL);
        ceremony = WebAuthnCeremony.startRegistration(new byte[32], account.getId(), ticket.id());
        when(ticketService.resolve("raw")).thenReturn(Mono.just(ticket));
        when(ceremonyRepository.consume(ceremony.id(), CeremonyType.REGISTRATION)).thenReturn(Mono.just(ceremony));
        when(webAuthnVerifier.verifyRegistration("{json}", ceremony.challenge(), RP)).thenReturn(verified);
        when(ticketService.consume(ticket)).thenReturn(Mono.empty());
        when(userRepository.lockById(account.getId())).thenReturn(Mono.just(account));
        when(passkeyRepository.countByUserId(account.getId())).thenReturn(Mono.just(1L));

        // Act + Assert
        StepVerifier.create(workflow.register(command(ceremony.id(), null)))
                .expectError(InvalidTicketException.class).verify();
        verify(passkeyRepository, never()).insert(any());
        verify(preregistrationRepository).deleteById(preregistration.id());
        verify(auditService).record("onboarding_preregistration", preregistration.id(),
                AuthAuditEvents.PASSKEY_REJECTED, null, Map.of("reason", "account_has_passkeys"));
    }

    @Test
    void register_accountOfTheEmailAppearedAfterTheRedemption_isRejected() {
        // Arrange: EC-04 (decision of the developer, 2026-11-06): its user handle is not the one in the passkey
        when(userRepository.findAllByEmailIgnoreCase(EMAIL))
                .thenReturn(Flux.just(WalletUser.create(EMAIL, new byte[WalletUser.USER_HANDLE_LENGTH])));

        // Act + Assert
        StepVerifier.create(workflow.register(command(ceremony.id(), null)))
                .expectError(InvalidTicketException.class).verify();
        verify(userRepository, never()).save(any());
        verify(passkeyRepository, never()).insert(any());
        verify(auditService).record("onboarding_preregistration", preregistration.id(),
                AuthAuditEvents.PASSKEY_REJECTED, null, Map.of("reason", "account_appeared"));
    }

    @Test
    void register_twoAccountsOfTheEmailThatDifferOnlyInCase_isRejected() {
        // Arrange: EC-15, P16 - the lookup ignores case; several accounts also count as an existing one
        when(userRepository.findAllByEmailIgnoreCase(EMAIL)).thenReturn(Flux.just(
                WalletUser.create(EMAIL, new byte[WalletUser.USER_HANDLE_LENGTH]),
                WalletUser.create("ANA@example.com", new byte[WalletUser.USER_HANDLE_LENGTH])));

        // Act + Assert
        StepVerifier.create(workflow.register(command(ceremony.id(), null)))
                .expectError(InvalidTicketException.class).verify();
        verify(userRepository, never()).save(any());
        verify(passkeyRepository, never()).insert(any());
        verify(auditService).record("onboarding_preregistration", preregistration.id(),
                AuthAuditEvents.PASSKEY_REJECTED, null, Map.of("reason", "account_appeared"));
    }

    @Test
    void register_concurrentCreationOfTheSameAccount_rejectsTheSecond() {
        // Arrange: EC-04, two onboarding tickets of one email registered at once
        when(userRepository.findAllByEmailIgnoreCase(EMAIL)).thenReturn(Flux.empty());
        when(userRepository.save(any())).thenReturn(Mono.error(new DuplicateAccountException()));

        // Act + Assert
        StepVerifier.create(workflow.register(command(ceremony.id(), null)))
                .expectError(InvalidTicketException.class).verify();
        verify(passkeyRepository, never()).insert(any());
    }

    @Test
    void register_ceremonyOfAnotherPreregistration_isRejected() {
        // Arrange: EC-13, decision P9 - both have no account, so only the ticket binds them
        var foreign = WebAuthnCeremony.startRegistration(new byte[32], null, UUID.randomUUID());
        when(ceremonyRepository.consume(foreign.id(), CeremonyType.REGISTRATION)).thenReturn(Mono.just(foreign));

        // Act + Assert
        StepVerifier.create(workflow.register(command(foreign.id(), null)))
                .expectErrorSatisfies(e -> assertThat(e).hasMessageContaining("ceremony_mismatch")
                        .isInstanceOf(com.eudistack.ebw.domain.model.exception.RegistrationFailedException.class))
                .verify();
        verify(userRepository, never()).save(any());
    }

    @Test
    void register_passkeyCustodyWithoutPrf_createsNothing() {
        // Arrange: EC-11
        when(custodyPolicy.isPasskeyCustody()).thenReturn(Mono.just(true));

        // Act + Assert
        StepVerifier.create(workflow.register(command(ceremony.id(), false)))
                .expectError(PasskeyPrfUnsupportedException.class).verify();
        verify(userRepository, never()).save(any());
        verify(ticketService, never()).consume(any());
    }

    @Test
    void register_ticketWithoutAccountNorPreregistration_isInvalid() {
        // Arrange: EC-07, defense in depth (the database also forbids it)
        var orphan = new RegistrationTicket(UUID.randomUUID(), null, null, "x", Instant.now().plusSeconds(60), null,
                Instant.now());
        when(ticketService.resolve("raw")).thenReturn(Mono.just(orphan));

        // Act + Assert
        StepVerifier.create(workflow.register(command(ceremony.id(), null)))
                .expectError(InvalidTicketException.class).verify();
        verify(userRepository, never()).save(any());
    }

    @Test
    void register_preregistrationGone_isInvalid() {
        // Arrange: the pre-registration expired and was cleaned up
        when(preregistrationRepository.findById(preregistration.id())).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(workflow.register(command(ceremony.id(), null)))
                .expectError(InvalidTicketException.class).verify();
        verify(ceremonyRepository, never()).consume(any(), any());
    }

    @Test
    void startRegistration_accountOfTheTicket_listsItsPasskeys() {
        // Arrange: EC-01, the account exists without passkeys
        var account = WalletUser.create(EMAIL, new byte[WalletUser.USER_HANDLE_LENGTH]);
        ticket = RegistrationTicket.issueForPreregistration(account.getId(), preregistration.id(), "rt-hash", RegistrationTicket.TTL);
        when(ticketService.resolve("raw")).thenReturn(Mono.just(ticket));
        when(userRepository.findById(account.getId())).thenReturn(Mono.just(account));
        when(passkeyRepository.findByUserId(account.getId())).thenReturn(Flux.empty());

        // Act + Assert
        StepVerifier.create(workflow.startRegistration("raw"))
                .assertNext(options -> assertThat(options.userHandle()).isEqualTo(account.getWebauthnUserHandle()))
                .verifyComplete();
    }
}
