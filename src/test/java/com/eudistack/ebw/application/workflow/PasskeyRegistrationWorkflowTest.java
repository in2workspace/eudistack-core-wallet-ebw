package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.application.workflow.PasskeyRegistrationWorkflow.RegisterPasskeyCommand;
import com.eudistack.ebw.domain.model.CeremonyType;
import com.eudistack.ebw.domain.model.IssuedSession;
import com.eudistack.ebw.domain.model.RegistrationTicket;
import com.eudistack.ebw.domain.model.RelyingPartySettings;
import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.VerifiedPasskeyRegistration;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.model.WebAuthnCeremony;
import com.eudistack.ebw.domain.model.exception.PasskeyPrfUnsupportedException;
import com.eudistack.ebw.domain.model.exception.RegistrationFailedException;
import com.eudistack.ebw.domain.model.exception.WebAuthnVerificationException;
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
import com.eudistack.ebw.support.TestPasskeys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link PasskeyRegistrationWorkflow}. */
@ExtendWith(MockitoExtension.class)
class PasskeyRegistrationWorkflowTest {

    private static final RelyingPartySettings RP = new RelyingPartySettings("rp.example", "Wallet",
            List.of("https://rp.example"));

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

    private PasskeyRegistrationWorkflow workflow;
    private WalletUser user;
    private RegistrationTicket ticket;
    private WebAuthnCeremony ceremony;
    private VerifiedPasskeyRegistration verified;
    private IssuedSession session;

    @BeforeEach
    void setUp() {
        workflow = new PasskeyRegistrationWorkflow(ticketService, userRepository, passkeyRepository, ceremonyRepository,
                settingsService, custodyPolicy, webAuthnVerifier, randomGenerator, sessionOpener, emailSender,
                auditService, transactionRunner);
        user = TestPasskeys.user("holder@example.com");
        ticket = RegistrationTicket.issue(user.getId(), "hash");
        ceremony = WebAuthnCeremony.start(CeremonyType.REGISTRATION, new byte[32], user.getId());
        verified = new VerifiedPasskeyRegistration("cred-1", new byte[] {1}, null, 0, List.of("internal"), true, true,
                true, "none");
        session = new IssuedSession("access", 300, "refresh", UUID.randomUUID(), UUID.randomUUID(), Instant.now());
        lenient().when(ticketService.resolve("raw")).thenReturn(Mono.just(ticket));
        lenient().when(userRepository.findById(user.getId())).thenReturn(Mono.just(user));
        lenient().when(ceremonyRepository.consume(ceremony.id(), CeremonyType.REGISTRATION)).thenReturn(Mono.just(ceremony));
        lenient().when(settingsService.relyingParty()).thenReturn(Mono.just(RP));
        lenient().when(custodyPolicy.isPasskeyCustody()).thenReturn(Mono.just(false));
        lenient().when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());
        lenient().when(transactionRunner.inTransaction(any())).thenAnswer(inv -> inv.getArgument(0));
    }

    private RegisterPasskeyCommand command(Boolean prfSupported) {
        return new RegisterPasskeyCommand("raw", ceremony.id(), "{json}", prfSupported, null, "ua", null);
    }

    private void verifiesAndStores(long previousPasskeys) {
        when(webAuthnVerifier.verifyRegistration("{json}", ceremony.challenge(), RP)).thenReturn(verified);
        when(passkeyRepository.findByCredentialId("cred-1")).thenReturn(Mono.empty());
        when(ticketService.consume(ticket)).thenReturn(Mono.empty());
        when(passkeyRepository.countByUserId(user.getId())).thenReturn(Mono.just(previousPasskeys));
        lenient().when(passkeyRepository.insert(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        lenient().when(sessionOpener.open(eq(user), any(), eq(null), eq("registration"))).thenReturn(Mono.just(session));
    }

    @Test
    void register_firstPasskey_storesItInOneTransactionAndOpensSessionWithoutNotice() {
        // Arrange
        verifiesAndStores(0);

        // Act + Assert
        StepVerifier.create(workflow.register(command(null))).expectNext(session).verifyComplete();
        verify(transactionRunner).inTransaction(any());
        verify(emailSender, never()).sendNewPasskeyNotice(anyString());
    }

    @Test
    void register_missingDisplayName_usesTheDefaultName() {
        // Arrange
        verifiesAndStores(0);

        // Act
        StepVerifier.create(workflow.register(command(null))).expectNextCount(1).verifyComplete();

        // Assert
        var stored = org.mockito.ArgumentCaptor.forClass(UserPasskey.class);
        verify(passkeyRepository).insert(stored.capture());
        assertThat(stored.getValue().getDisplayName()).isEqualTo("Passkey");
    }

    @Test
    void register_secondPasskey_emailsTheHolderAndAuditsIt() {
        // Arrange
        verifiesAndStores(1);
        when(emailSender.sendNewPasskeyNotice("holder@example.com")).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(workflow.register(command(null))).expectNext(session).verifyComplete();
        verify(auditService).record(eq("passkey"), any(), eq(AuthAuditEvents.NEW_PASSKEY_NOTICE_SENT), eq(user.getId()),
                eq(Map.of()));
    }

    @Test
    void register_noticeFails_auditsTheFailureAndStillOpensSession() {
        // Arrange
        verifiesAndStores(1);
        when(emailSender.sendNewPasskeyNotice("holder@example.com"))
                .thenReturn(Mono.error(new IllegalStateException("smtp down")));

        // Act + Assert
        StepVerifier.create(workflow.register(command(null))).expectNext(session).verifyComplete();
        verify(auditService).record(eq("passkey"), any(), eq(AuthAuditEvents.NEW_PASSKEY_NOTICE_FAILED),
                eq(user.getId()), eq(Map.of()));
    }

    @Test
    void register_passkeyCustodyWithoutPrf_rejectsWithoutVerifyingNorStoring() {
        // Arrange
        when(custodyPolicy.isPasskeyCustody()).thenReturn(Mono.just(true));

        // Act + Assert
        StepVerifier.create(workflow.register(command(false))).expectError(PasskeyPrfUnsupportedException.class).verify();
        verify(auditService).record("user", user.getId(), AuthAuditEvents.PASSKEY_REJECTED, user.getId(),
                Map.of("reason", "prf_unsupported"));
        verify(webAuthnVerifier, never()).verifyRegistration(any(), any(), any());
        verify(passkeyRepository, never()).insert(any());
    }

    @Test
    void register_passkeyCustodyWithPrfDeclaredButNotInTheResponse_trustsTheClientAndStoresItWithPrf() {
        // Arrange: the registration response reports no PRF (Safari only reports it on get()). The
        // service cannot check it: the extension outputs are not signed. The Wallet App's PRF check decides.
        when(custodyPolicy.isPasskeyCustody()).thenReturn(Mono.just(true));
        verifiesAndStores(0);

        // Act
        StepVerifier.create(workflow.register(command(true))).expectNext(session).verifyComplete();

        // Assert
        var stored = org.mockito.ArgumentCaptor.forClass(UserPasskey.class);
        verify(passkeyRepository).insert(stored.capture());
        assertThat(stored.getValue().isPrfEnabled()).isTrue();
        verify(auditService).record(eq("passkey"), any(), eq(AuthAuditEvents.PASSKEY_REGISTERED), eq(user.getId()),
                eq(Map.of("prf_enabled", true)));
    }

    @Test
    void register_unknownCeremony_rejectsAndAuditsTheReason() {
        // Arrange
        when(ceremonyRepository.consume(ceremony.id(), CeremonyType.REGISTRATION)).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(workflow.register(command(null))).expectError(RegistrationFailedException.class).verify();
        verify(auditService).record("user", user.getId(), AuthAuditEvents.PASSKEY_REJECTED, user.getId(),
                Map.of("reason", "ceremony_invalid"));
    }

    @Test
    void register_ceremonyOfAnotherAccount_isRejected() {
        // Arrange
        var foreign = WebAuthnCeremony.start(CeremonyType.REGISTRATION, new byte[32], UUID.randomUUID());
        when(ceremonyRepository.consume(ceremony.id(), CeremonyType.REGISTRATION)).thenReturn(Mono.just(foreign));

        // Act + Assert
        StepVerifier.create(workflow.register(command(null))).expectError(RegistrationFailedException.class).verify();
        verify(auditService).record("user", user.getId(), AuthAuditEvents.PASSKEY_REJECTED, user.getId(),
                Map.of("reason", "ceremony_mismatch"));
    }

    @Test
    void register_responseDoesNotVerify_rejectsWithoutConsumingTheTicket() {
        // Arrange
        when(webAuthnVerifier.verifyRegistration("{json}", ceremony.challenge(), RP))
                .thenThrow(new WebAuthnVerificationException("BadChallenge"));

        // Act + Assert
        StepVerifier.create(workflow.register(command(null))).expectError(RegistrationFailedException.class).verify();
        verify(auditService).record("user", user.getId(), AuthAuditEvents.PASSKEY_REJECTED, user.getId(),
                Map.of("reason", "verification_failed"));
        verify(ticketService, never()).consume(any());
    }

    @Test
    void register_credentialAlreadyInTheTenant_isRejected() {
        // Arrange
        when(webAuthnVerifier.verifyRegistration("{json}", ceremony.challenge(), RP)).thenReturn(verified);
        when(passkeyRepository.findByCredentialId("cred-1"))
                .thenReturn(Mono.just(TestPasskeys.create(UUID.randomUUID(), "cred-1", "x", null)));

        // Act + Assert
        StepVerifier.create(workflow.register(command(null))).expectError(RegistrationFailedException.class).verify();
        verify(auditService).record("user", user.getId(), AuthAuditEvents.PASSKEY_REJECTED, user.getId(),
                Map.of("reason", "credential_already_registered"));
    }

    @Test
    void register_insertRaceLost_isRejectedAsDuplicate() {
        // Arrange
        verifiesAndStores(0);
        doReturn(Mono.error(new RegistrationFailedException(
                        com.eudistack.ebw.domain.model.AuthRejectionReason.CREDENTIAL_ALREADY_REGISTERED)))
                .when(passkeyRepository).insert(any());

        // Act + Assert
        StepVerifier.create(workflow.register(command(null))).expectError(RegistrationFailedException.class).verify();
        verify(auditService).record("user", user.getId(), AuthAuditEvents.PASSKEY_REJECTED, user.getId(),
                Map.of("reason", "credential_already_registered"));
    }

    @Test
    void startRegistration_passkeyCustody_requestsPrfAndExcludesTheAccountPasskeys() {
        // Arrange
        var existing = TestPasskeys.create(user.getId(), "cred-0", "Laptop", null);
        when(custodyPolicy.isPasskeyCustody()).thenReturn(Mono.just(true));
        when(passkeyRepository.findByUserId(user.getId())).thenReturn(Flux.just(existing));
        when(randomGenerator.generateBytes(32)).thenReturn(new byte[32]);
        when(ceremonyRepository.insert(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Act + Assert
        StepVerifier.create(workflow.startRegistration("raw"))
                .assertNext(options -> {
                    assertThat(options.requestPrf()).isTrue();
                    assertThat(options.excludeCredentials()).containsExactly(existing);
                    assertThat(options.userName()).isEqualTo("holder@example.com");
                    assertThat(options.userHandle()).isEqualTo(user.getWebauthnUserHandle());
                })
                .verifyComplete();
    }
}
