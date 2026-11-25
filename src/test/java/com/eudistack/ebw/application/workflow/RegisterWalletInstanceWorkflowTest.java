package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.application.workflow.RegisterWalletInstanceWorkflow.RegisterCommand;
import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.model.WalletInstance;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.model.exception.InvalidWalletInstanceException;
import com.eudistack.ebw.domain.model.exception.RateLimitExceededException;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.eudistack.ebw.domain.repository.WalletInstanceRepository;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.spi.IpRateLimiter;
import com.eudistack.ebw.domain.spi.TransactionRunner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Unit tests for {@link RegisterWalletInstanceWorkflow} (EUD-15 FR-01 to FR-04, FR-08, design §2.1). */
@ExtendWith(MockitoExtension.class)
class RegisterWalletInstanceWorkflowTest {

    private static final String TENANT = "cgcom";

    @Mock private WalletInstanceRepository instanceRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private WalletUserRepository userRepository;
    @Mock private AuditService auditService;
    @Mock private TransactionRunner transactionRunner;
    @Mock private IpRateLimiter rateLimiter;
    @Mock private EmailLocales emailLocales;
    @Mock private WalletInstanceNotices notices;

    private RegisterWalletInstanceWorkflow workflow;
    private WalletSession session;
    private WalletUser user;

    @BeforeEach
    void setUp() {
        workflow = new RegisterWalletInstanceWorkflow(instanceRepository, refreshTokenRepository, userRepository,
                auditService, transactionRunner, rateLimiter, emailLocales, notices);
        user = WalletUser.create("ana@example.com", new byte[WalletUser.USER_HANDLE_LENGTH]);
        session = new WalletSession(user.getId(), UUID.randomUUID(), UUID.randomUUID(), null);
        lenient().when(rateLimiter.check(anyString(), eq(20))).thenReturn(Mono.empty());
        lenient().when(transactionRunner.inTransaction(any())).thenAnswer(inv -> inv.getArgument(0));
        lenient().when(instanceRepository.countByUserId(user.getId())).thenReturn(Mono.just(0L));
        lenient().when(instanceRepository.insert(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        lenient().when(refreshTokenRepository.bindSession(eq(session.sessionId()), any())).thenReturn(Mono.just(1L));
        lenient().when(refreshTokenRepository.clearPasskeyNoticePending(session.sessionId())).thenReturn(Mono.just(false));
        lenient().when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());
        lenient().when(emailLocales.rememberRequestLanguage(user.getId())).thenReturn(Mono.empty());
        lenient().when(userRepository.findById(user.getId())).thenReturn(Mono.just(user));
        lenient().when(notices.deviceRegistered(any())).thenReturn(Mono.empty());
        lenient().when(userRepository.lockById(user.getId())).thenReturn(Mono.just(user));
    }

    private Mono<WalletInstance> register(String name, String type) {
        return workflow.register(session, new RegisterCommand(name, type))
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TENANT));
    }

    @Test
    void register_validRequest_storesAnActiveInstanceAndBindsTheSessionInOneTransaction() {
        // AC-01, AC-03
        StepVerifier.create(register(" iPhone · Safari ", "mobile"))
                .assertNext(instance -> {
                    assertThat(instance.isActive()).isTrue();
                    assertThat(instance.displayName()).isEqualTo("iPhone · Safari");
                    assertThat(instance.deviceType()).isEqualTo(WalletInstance.DeviceType.MOBILE);
                    assertThat(instance.registeredPasskeyId()).isEqualTo(session.passkeyId());
                    assertThat(instance.userId()).isEqualTo(user.getId());
                })
                .verifyComplete();

        var stored = ArgumentCaptor.forClass(WalletInstance.class);
        verify(instanceRepository).insert(stored.capture());
        verify(refreshTokenRepository).bindSession(session.sessionId(), stored.getValue().id());
        verify(transactionRunner).inTransaction(any());
        verify(auditService).record(eq(WalletInstanceAuditEvents.ENTITY_WALLET_INSTANCE), eq(stored.getValue().id()),
                eq(WalletInstanceAuditEvents.WALLET_INSTANCE_REGISTERED), eq(user.getId()), any());
    }

    @Test
    void register_validRequest_storesTheLanguageBeforeTheEmail() {
        // EUD-8 AD-10: the registration stores the language of Accept-Language
        StepVerifier.create(register("Mac · Chrome", "desktop")).expectNextCount(1).verifyComplete();

        var order = inOrder(emailLocales, notices);
        order.verify(emailLocales).rememberRequestLanguage(user.getId());
        order.verify(notices).deviceRegistered(any());
    }

    @Test
    void register_firstInstanceOfAFreshAccount_isTheFirstDeviceOfANewAccount() {
        // FR-08: the email confirms the complete sign-up
        StepVerifier.create(register("Mac · Chrome", "desktop")).expectNextCount(1).verifyComplete();

        var registration = ArgumentCaptor.forClass(WalletInstanceNotices.Registration.class);
        verify(notices).deviceRegistered(registration.capture());
        assertThat(registration.getValue().firstOfNewAccount()).isTrue();
        assertThat(registration.getValue().passkeyAdded()).isFalse();
    }

    @Test
    void register_accountWithAnInstanceAlready_isANewDevice() {
        when(instanceRepository.countByUserId(user.getId())).thenReturn(Mono.just(1L));

        StepVerifier.create(register("Windows · Edge", "desktop")).expectNextCount(1).verifyComplete();

        var registration = ArgumentCaptor.forClass(WalletInstanceNotices.Registration.class);
        verify(notices).deviceRegistered(registration.capture());
        assertThat(registration.getValue().firstOfNewAccount()).isFalse();
    }

    @Test
    void register_firstInstanceOfAnOldAccount_isANewDevice() {
        // An account from before the Wallet Instances: its first device is not a new sign-up
        var old = new WalletUser(user.getId(), user.getEmail(), new byte[32], Instant.now().minus(Duration.ofDays(30)),
                Instant.now(), null);
        when(userRepository.findById(user.getId())).thenReturn(Mono.just(old));

        StepVerifier.create(register("Windows · Edge", "desktop")).expectNextCount(1).verifyComplete();

        var registration = ArgumentCaptor.forClass(WalletInstanceNotices.Registration.class);
        verify(notices).deviceRegistered(registration.capture());
        assertThat(registration.getValue().firstOfNewAccount()).isFalse();
    }

    @Test
    void register_sessionThatAddedAPasskey_takesTheMarkSoTheEmailSaysIt() {
        // EUD-8 FR-10, AD-11: one email, the new-device one with the passkey line
        when(instanceRepository.countByUserId(user.getId())).thenReturn(Mono.just(1L));
        when(refreshTokenRepository.clearPasskeyNoticePending(session.sessionId())).thenReturn(Mono.just(true));

        StepVerifier.create(register("Windows · Edge", "desktop")).expectNextCount(1).verifyComplete();

        var registration = ArgumentCaptor.forClass(WalletInstanceNotices.Registration.class);
        verify(notices).deviceRegistered(registration.capture());
        assertThat(registration.getValue().passkeyAdded()).isTrue();
    }

    @ParameterizedTest
    @CsvSource(value = {"'',mobile", "'   ',mobile", "iPhone,phone", "iPhone,MOBILE", "iPhone,"})
    void register_invalidNameOrType_isRejectedWithoutStoringAnything(String name, String type) {
        // AC-02
        StepVerifier.create(register(name, type)).expectError(InvalidWalletInstanceException.class).verify();

        verifyNoInteractions(instanceRepository, refreshTokenRepository, notices);
    }

    @Test
    void register_nameOfFiftyOneCharacters_isRejected() {
        StepVerifier.create(register("a".repeat(51), "desktop")).expectError(InvalidWalletInstanceException.class)
                .verify();
        verify(instanceRepository, never()).insert(any());
    }

    @Test
    void register_moreThanTwentyPerAccountAndHour_isRejectedBeforeStoring() {
        // design §2.1: 20 registrations per account and hour, keyed by tenant and account
        when(rateLimiter.check("wallet-instance-registration:" + TENANT + ":" + user.getId(), 20))
                .thenReturn(Mono.error(new RateLimitExceededException(3600)));

        StepVerifier.create(register("Mac · Chrome", "desktop")).expectError(RateLimitExceededException.class).verify();

        verify(instanceRepository, never()).insert(any());
    }

    @Test
    void register_storingFails_sendsNoEmail() {
        when(refreshTokenRepository.bindSession(eq(session.sessionId()), any()))
                .thenReturn(Mono.error(new IllegalStateException("db down")));

        StepVerifier.create(register("Mac · Chrome", "desktop")).expectError(IllegalStateException.class).verify();

        verify(notices, never()).deviceRegistered(any());
    }
}
