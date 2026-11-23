package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.AccountCompleteNotice;
import com.eudistack.ebw.domain.model.NewDeviceNotice;
import com.eudistack.ebw.domain.model.NewPasskeyNotice;
import com.eudistack.ebw.domain.model.WalletInstance;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.spi.EmailSender;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link WalletInstanceNotices}: a single email per device registration (EUD-15 FR-08, AC-09, AC-10). */
@ExtendWith(MockitoExtension.class)
class WalletInstanceNoticesTest {

    private static final Locale CA = Locale.of("ca");
    private static final String DEVICES = "https://cgcom.eudistack.net/wallet/tabs/devices";

    @Mock private EmailSender emailSender;
    @Mock private EmailLocales emailLocales;
    @Mock private WalletLinks walletLinks;
    @Mock private AuditService auditService;
    @Mock private NotifyOnboardingAccountCreatedWorkflow onboardingNotice;

    private WalletInstanceNotices notices;
    private WalletUser user;
    private WalletInstance instance;

    @BeforeEach
    void setUp() {
        notices = new WalletInstanceNotices(emailSender, emailLocales, walletLinks, auditService, onboardingNotice);
        user = WalletUser.create("ana@example.com", new byte[WalletUser.USER_HANDLE_LENGTH]);
        instance = WalletInstance.register(user.getId(), "Windows · Edge", WalletInstance.DeviceType.DESKTOP,
                UUID.randomUUID());
        lenient().when(emailLocales.ofHolder(user)).thenReturn(Mono.just(CA));
        lenient().when(walletLinks.devices()).thenReturn(Mono.just(DEVICES));
        lenient().when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());
        lenient().when(onboardingNotice.notify(any(), anyString())).thenReturn(Mono.just(false));
        lenient().when(emailSender.sendAccountCompleteNotice(anyString(), any(), any())).thenReturn(Mono.empty());
        lenient().when(emailSender.sendNewDeviceNotice(anyString(), any(), any())).thenReturn(Mono.empty());
        lenient().when(emailSender.sendNewPasskeyNotice(anyString(), any(), any())).thenReturn(Mono.empty());
    }

    private WalletInstanceNotices.Registration registration(boolean firstOfNewAccount, boolean passkeyAdded) {
        return new WalletInstanceNotices.Registration(user, instance, firstOfNewAccount, passkeyAdded);
    }

    @Test
    void deviceRegistered_passkeyOfAnOnboardingTicket_sendsOnlyTheNewAccountEmail() {
        // AC-09: one email, the new-account one with "it was not me" and the name of the device
        when(onboardingNotice.notify(instance.registeredPasskeyId(), "Windows · Edge")).thenReturn(Mono.just(true));

        StepVerifier.create(notices.deviceRegistered(registration(true, false))).verifyComplete();

        verify(emailSender, never()).sendAccountCompleteNotice(anyString(), any(), any());
        verify(emailSender, never()).sendNewDeviceNotice(anyString(), any(), any());
    }

    @Test
    void deviceRegistered_firstDeviceOfANewAccount_confirmsTheCompleteSignUp() {
        StepVerifier.create(notices.deviceRegistered(registration(true, false))).verifyComplete();

        verify(emailSender).sendAccountCompleteNotice("ana@example.com",
                new AccountCompleteNotice(instance.createdAt(), "Windows · Edge"), CA);
        verify(auditService).record(WalletInstanceAuditEvents.ENTITY_WALLET_INSTANCE, instance.id(),
                WalletInstanceAuditEvents.WALLET_INSTANCE_NOTICE_SENT, user.getId(), Map.of());
    }

    @Test
    void deviceRegistered_otherDevice_sendsTheNewDeviceEmailWithTheLinkToDevices() {
        // AC-10
        StepVerifier.create(notices.deviceRegistered(registration(false, false))).verifyComplete();

        var notice = ArgumentCaptor.forClass(NewDeviceNotice.class);
        verify(emailSender).sendNewDeviceNotice(eq("ana@example.com"), notice.capture(), eq(CA));
        assertThat(notice.getValue().deviceName()).isEqualTo("Windows · Edge");
        assertThat(notice.getValue().devicesUrl()).isEqualTo(DEVICES);
        assertThat(notice.getValue().passkeyAdded()).isFalse();
    }

    @Test
    void deviceRegistered_sessionThatAddedAPasskey_saysItInTheNewDeviceEmail() {
        // EUD-8 AC-07: a single email
        StepVerifier.create(notices.deviceRegistered(registration(false, true))).verifyComplete();

        var notice = ArgumentCaptor.forClass(NewDeviceNotice.class);
        verify(emailSender).sendNewDeviceNotice(anyString(), notice.capture(), any());
        assertThat(notice.getValue().passkeyAdded()).isTrue();
        verify(emailSender, never()).sendNewPasskeyNotice(anyString(), any(), any());
    }

    @Test
    void deviceRegistered_tenantWithoutWalletUrl_sendsTheEmailWithoutTheLink() {
        when(walletLinks.devices()).thenReturn(Mono.empty());

        StepVerifier.create(notices.deviceRegistered(registration(false, false))).verifyComplete();

        var notice = ArgumentCaptor.forClass(NewDeviceNotice.class);
        verify(emailSender).sendNewDeviceNotice(anyString(), notice.capture(), any());
        assertThat(notice.getValue().devicesUrl()).isNull();
    }

    @Test
    void deviceRegistered_emailFails_tracesTheFailureAndCompletes() {
        // AC-10: the device stays registered and the failure is traced
        when(emailSender.sendNewDeviceNotice(anyString(), any(), any()))
                .thenReturn(Mono.error(new IllegalStateException("smtp down")));

        StepVerifier.create(notices.deviceRegistered(registration(false, false))).verifyComplete();

        verify(auditService).record(WalletInstanceAuditEvents.ENTITY_WALLET_INSTANCE, instance.id(),
                WalletInstanceAuditEvents.WALLET_INSTANCE_NOTICE_FAILED, user.getId(), Map.of());
    }

    @Test
    void deviceRegistered_slowEmail_isCutAfterFiveSecondsAndTraced() {
        when(emailSender.sendNewDeviceNotice(anyString(), any(), any())).thenReturn(Mono.never());

        StepVerifier.withVirtualTime(() -> notices.deviceRegistered(registration(false, false)))
                .thenAwait(WalletInstanceNotices.NOTICE_TIMEOUT.plusSeconds(1))
                .verifyComplete();

        verify(auditService).record(WalletInstanceAuditEvents.ENTITY_WALLET_INSTANCE, instance.id(),
                WalletInstanceAuditEvents.WALLET_INSTANCE_NOTICE_FAILED, user.getId(), Map.of());
    }

    @Test
    void passkeyAdded_holder_getsTheNewPasskeyEmailInTheLanguageOfTheAccount() {
        var passkeyId = UUID.randomUUID();
        var addedAt = Instant.parse("2026-10-30T09:42:00Z");

        StepVerifier.create(notices.passkeyAdded(user, passkeyId, addedAt)).verifyComplete();

        verify(emailSender).sendNewPasskeyNotice("ana@example.com", new NewPasskeyNotice(addedAt, DEVICES), CA);
        verify(auditService).record("passkey", passkeyId, AuthAuditEvents.NEW_PASSKEY_NOTICE_SENT, user.getId(),
                Map.of());
    }

    @Test
    void passkeyAdded_emailFails_tracesTheFailure() {
        var passkeyId = UUID.randomUUID();
        when(emailSender.sendNewPasskeyNotice(anyString(), any(), any()))
                .thenReturn(Mono.error(new IllegalStateException("smtp down")));

        StepVerifier.create(notices.passkeyAdded(user, passkeyId, Instant.now())).verifyComplete();

        verify(auditService).record("passkey", passkeyId, AuthAuditEvents.NEW_PASSKEY_NOTICE_FAILED, user.getId(),
                Map.of());
    }
}
