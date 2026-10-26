package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.application.workflow.PasskeyAuthenticationWorkflow.OpenSessionCommand;
import com.eudistack.ebw.domain.model.CeremonyType;
import com.eudistack.ebw.domain.model.IssuedSession;
import com.eudistack.ebw.domain.model.PasskeyAssertion;
import com.eudistack.ebw.domain.model.RegistrationTicket;
import com.eudistack.ebw.domain.model.RelyingPartySettings;
import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.VerifiedPasskeyAssertion;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.model.WebAuthnCeremony;
import com.eudistack.ebw.domain.model.exception.AuthenticationFailedException;
import com.eudistack.ebw.domain.model.exception.UnknownCredentialException;
import com.eudistack.ebw.domain.model.exception.WebAuthnVerificationException;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.repository.WebAuthnCeremonyRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.RegistrationTicketService;
import com.eudistack.ebw.domain.service.WalletAuthSettingsService;
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
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link PasskeyAuthenticationWorkflow}. */
@ExtendWith(MockitoExtension.class)
class PasskeyAuthenticationWorkflowTest {

    private static final RelyingPartySettings RP = new RelyingPartySettings("rp.example", "Wallet",
            List.of("https://rp.example"));

    @Mock private RegistrationTicketService ticketService;
    @Mock private WalletUserRepository userRepository;
    @Mock private UserPasskeyRepository passkeyRepository;
    @Mock private WebAuthnCeremonyRepository ceremonyRepository;
    @Mock private WalletAuthSettingsService settingsService;
    @Mock private WebAuthnVerifier webAuthnVerifier;
    @Mock private SecureRandomGenerator randomGenerator;
    @Mock private SessionOpener sessionOpener;
    @Mock private AuditService auditService;
    @Mock private TransactionRunner transactionRunner;

    private PasskeyAuthenticationWorkflow workflow;
    private WalletUser user;
    private UserPasskey passkey;
    private WebAuthnCeremony ceremony;
    private IssuedSession session;

    @BeforeEach
    void setUp() {
        workflow = new PasskeyAuthenticationWorkflow(ticketService, userRepository, passkeyRepository,
                ceremonyRepository, settingsService, webAuthnVerifier, randomGenerator, sessionOpener, auditService,
                transactionRunner);
        user = TestPasskeys.user("holder@example.com");
        passkey = TestPasskeys.create(user.getId(), "cred-1", "Phone", null);
        ceremony = WebAuthnCeremony.start(CeremonyType.AUTHENTICATION, new byte[32], null);
        session = new IssuedSession("access", 300, "refresh", UUID.randomUUID(), passkey.getId(), Instant.now());
        lenient().when(transactionRunner.inTransaction(any())).thenAnswer(inv -> inv.getArgument(0));
        lenient().when(ceremonyRepository.consume(ceremony.id(), CeremonyType.AUTHENTICATION))
                .thenReturn(Mono.just(ceremony));
        lenient().when(passkeyRepository.findByCredentialId("cred-1")).thenReturn(Mono.just(passkey));
        lenient().when(userRepository.findById(user.getId())).thenReturn(Mono.just(user));
        lenient().when(settingsService.relyingParty()).thenReturn(Mono.just(RP));
        lenient().when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());
        lenient().when(sessionOpener.open(eq(user), eq(passkey.getId()), any(), any())).thenReturn(Mono.just(session));
    }

    private OpenSessionCommand command(String ticket) {
        return new OpenSessionCommand(ticket, ceremony.id(), "{json}", null);
    }

    private void assertion(byte[] userHandle) {
        when(webAuthnVerifier.readAssertion("{json}")).thenReturn(new PasskeyAssertion("cred-1", userHandle));
    }

    private void verifies(long signCount) {
        when(webAuthnVerifier.verifyAuthentication("{json}", ceremony.challenge(), RP, passkey))
                .thenReturn(new VerifiedPasskeyAssertion(signCount, true, true));
        when(passkeyRepository.recordAuthentication(eq(passkey.getId()), any())).thenReturn(Mono.just(true));
    }

    private void verifyRejected(String reason) {
        verify(auditService).record(eq("webauthn_ceremony"), eq(ceremony.id()), eq(AuthAuditEvents.ACCESS_REJECTED),
                any(), argThat((Map<String, Object> m) -> reason.equals(m.get("reason"))));
    }

    @Test
    void openSession_discoverablePasskey_opensSessionBoundToIt() {
        // Arrange
        assertion(user.getWebauthnUserHandle());
        verifies(1);

        // Act + Assert
        StepVerifier.create(workflow.openSession(command(null))).expectNext(session).verifyComplete();
    }

    @Test
    void openSession_unknownCredential_isRejectedAsUnknown() {
        // Arrange
        when(webAuthnVerifier.readAssertion("{json}")).thenReturn(new PasskeyAssertion("cred-x", new byte[32]));
        when(passkeyRepository.findByCredentialId("cred-x")).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(workflow.openSession(command(null))).expectError(UnknownCredentialException.class).verify();
        verifyRejected("unknown_credential");
    }

    @Test
    void openSession_userHandleOfAnotherAccount_isRejected() {
        // Arrange
        assertion(new byte[32]);

        // Act + Assert
        StepVerifier.create(workflow.openSession(command(null))).expectError(AuthenticationFailedException.class).verify();
        verifyRejected("user_handle_mismatch");
    }

    @Test
    void openSession_discoverableWithoutUserHandle_isRejected() {
        // Arrange
        assertion(null);

        // Act + Assert
        StepVerifier.create(workflow.openSession(command(null))).expectError(AuthenticationFailedException.class).verify();
        verifyRejected("user_handle_mismatch");
    }

    @Test
    void openSession_ticketAndNoUserHandle_isAcceptedAndConsumesTheTicket() {
        // Arrange
        var ticket = RegistrationTicket.issue(user.getId(), "hash");
        var bound = WebAuthnCeremony.start(CeremonyType.AUTHENTICATION, new byte[32], user.getId());
        when(ticketService.resolve("raw")).thenReturn(Mono.just(ticket));
        when(ceremonyRepository.consume(bound.id(), CeremonyType.AUTHENTICATION)).thenReturn(Mono.just(bound));
        when(webAuthnVerifier.readAssertion("{json}")).thenReturn(new PasskeyAssertion("cred-1", null));
        when(webAuthnVerifier.verifyAuthentication("{json}", bound.challenge(), RP, passkey))
                .thenReturn(new VerifiedPasskeyAssertion(1, true, true));
        when(passkeyRepository.recordAuthentication(eq(passkey.getId()), any())).thenReturn(Mono.just(true));
        when(ticketService.consume(ticket)).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(workflow.openSession(new OpenSessionCommand("raw", bound.id(), "{json}", null)))
                .expectNext(session).verifyComplete();
        verify(ticketService).consume(ticket);
    }

    @Test
    void openSession_ticketOfAnotherAccount_isRejected() {
        // Arrange
        var ticket = RegistrationTicket.issue(UUID.randomUUID(), "hash");
        var bound = WebAuthnCeremony.start(CeremonyType.AUTHENTICATION, new byte[32], ticket.userId());
        when(ticketService.resolve("raw")).thenReturn(Mono.just(ticket));
        when(ceremonyRepository.consume(bound.id(), CeremonyType.AUTHENTICATION)).thenReturn(Mono.just(bound));
        assertion(user.getWebauthnUserHandle());

        // Act + Assert
        StepVerifier.create(workflow.openSession(new OpenSessionCommand("raw", bound.id(), "{json}", null)))
                .expectError(AuthenticationFailedException.class).verify();
        verify(ticketService, never()).consume(any());
    }

    @Test
    void openSession_ceremonyBoundToATicketUsedWithout_isRejected() {
        // Arrange
        var bound = WebAuthnCeremony.start(CeremonyType.AUTHENTICATION, new byte[32], user.getId());
        when(ceremonyRepository.consume(bound.id(), CeremonyType.AUTHENTICATION)).thenReturn(Mono.just(bound));

        // Act + Assert
        StepVerifier.create(workflow.openSession(new OpenSessionCommand(null, bound.id(), "{json}", null)))
                .expectError(AuthenticationFailedException.class).verify();
    }

    @Test
    void openSession_signatureDoesNotVerify_isRejectedWithTheFixedReason() {
        // Arrange
        assertion(user.getWebauthnUserHandle());
        when(webAuthnVerifier.verifyAuthentication("{json}", ceremony.challenge(), RP, passkey))
                .thenThrow(new WebAuthnVerificationException("BadSignatureException with library details"));

        // Act + Assert
        StepVerifier.create(workflow.openSession(command(null))).expectError(AuthenticationFailedException.class).verify();
        verifyRejected("verification_failed");
        verify(sessionOpener, never()).open(any(), any(), any(), any());
    }

    @Test
    void openSession_counterRaceLost_isRejected() {
        // Arrange
        assertion(user.getWebauthnUserHandle());
        when(webAuthnVerifier.verifyAuthentication("{json}", ceremony.challenge(), RP, passkey))
                .thenReturn(new VerifiedPasskeyAssertion(5, true, true));
        when(passkeyRepository.recordAuthentication(eq(passkey.getId()), any())).thenReturn(Mono.just(false));

        // Act + Assert
        StepVerifier.create(workflow.openSession(command(null))).expectError(AuthenticationFailedException.class).verify();
        verifyRejected("sign_count_not_advanced");
    }

    @Test
    void openSession_usedCeremony_isRejected() {
        // Arrange
        when(ceremonyRepository.consume(ceremony.id(), CeremonyType.AUTHENTICATION)).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(workflow.openSession(command(null))).expectError(AuthenticationFailedException.class).verify();
        verifyRejected("ceremony_invalid");
    }

    @Test
    void startAuthentication_withTicket_allowsTheAccountPasskeys() {
        // Arrange
        var ticket = RegistrationTicket.issue(user.getId(), "hash");
        when(ticketService.resolve("raw")).thenReturn(Mono.just(ticket));
        when(passkeyRepository.findByUserId(user.getId())).thenReturn(Flux.just(passkey));
        when(randomGenerator.generateBytes(32)).thenReturn(new byte[32]);
        when(ceremonyRepository.insert(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Act + Assert
        StepVerifier.create(workflow.startAuthentication("raw"))
                .assertNext(options -> {
                    assertThat(options.allowCredentials()).containsExactly(passkey);
                    assertThat(options.rpId()).isEqualTo("rp.example");
                })
                .verifyComplete();
    }

    @Test
    void startAuthentication_withoutTicket_allowsNoCredential() {
        // Arrange
        when(randomGenerator.generateBytes(32)).thenReturn(new byte[32]);
        when(ceremonyRepository.insert(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Act + Assert
        StepVerifier.create(workflow.startAuthentication(null))
                .assertNext(options -> assertThat(options.allowCredentials()).isEmpty())
                .verifyComplete();
    }
}
