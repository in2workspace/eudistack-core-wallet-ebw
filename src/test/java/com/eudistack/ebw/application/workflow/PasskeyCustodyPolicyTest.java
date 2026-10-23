package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.wallet.profile.domain.exception.TenantUnknownException;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import com.eudistack.ebw.wallet.profile.domain.model.TenantWalletProfile;
import com.eudistack.ebw.wallet.profile.domain.model.WalletMode;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.UUID;

import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Unit tests for {@link PasskeyCustodyPolicy}. */
@ExtendWith(MockitoExtension.class)
class PasskeyCustodyPolicyTest {

    private static final UUID USER_ID = UUID.randomUUID();
    private static final UUID PASSKEY_ID = UUID.randomUUID();

    @Mock private WalletProfileQueryPort walletProfileQueryPort;

    private PasskeyCustodyPolicy policy;

    @BeforeEach
    void setUp() {
        policy = new PasskeyCustodyPolicy(walletProfileQueryPort);
    }

    private static TenantWalletProfile profile(KeyManager keyManager) {
        return new TenantWalletProfile("t", WalletMode.SERVER, keyManager, Instant.now(), Instant.now());
    }

    @Test
    void isPasskeyCustody_serverWithPasskeyPrf_isTrue() {
        when(walletProfileQueryPort.queryByCurrentTenant()).thenReturn(Mono.just(profile(KeyManager.PASSKEY_PRF)));

        StepVerifier.create(policy.isPasskeyCustody()).expectNext(true).verifyComplete();
    }

    @Test
    void isPasskeyCustody_serverWithDbKeys_isFalse() {
        when(walletProfileQueryPort.queryByCurrentTenant()).thenReturn(Mono.just(profile(KeyManager.DB)));

        StepVerifier.create(policy.isPasskeyCustody()).expectNext(false).verifyComplete();
    }

    @Test
    void isPasskeyCustody_tenantWithoutProfile_isFalse() {
        when(walletProfileQueryPort.queryByCurrentTenant())
                .thenReturn(Mono.error(new TenantUnknownException(TenantUnknownException.Reason.PROFILE_NOT_SEEDED)));

        StepVerifier.create(policy.isPasskeyCustody()).expectNext(false).verifyComplete();
    }

    @Test
    void visibleToSession_credentialOfTheSessionPasskey_isReturnedWithoutReadingTheProfile() {
        var credential = CredentialWorkflowFixtures.credential(USER_ID, true, PASSKEY_ID);

        StepVerifier.create(policy.visibleToSession(credential, PASSKEY_ID)).expectNext(credential).verifyComplete();
        verifyNoInteractions(walletProfileQueryPort);
    }

    @Test
    void visibleToSession_otherPasskeyWithPasskeyCustody_isEmpty() {
        var credential = CredentialWorkflowFixtures.credential(USER_ID, true, UUID.randomUUID());
        when(walletProfileQueryPort.queryByCurrentTenant()).thenReturn(Mono.just(profile(KeyManager.PASSKEY_PRF)));

        StepVerifier.create(policy.visibleToSession(credential, PASSKEY_ID)).verifyComplete();
    }

    @Test
    void visibleToSession_otherPasskeyWithServerCustody_isReturned() {
        var credential = CredentialWorkflowFixtures.credential(USER_ID, true, UUID.randomUUID());
        when(walletProfileQueryPort.queryByCurrentTenant()).thenReturn(Mono.just(profile(KeyManager.DB)));

        StepVerifier.create(policy.visibleToSession(credential, PASSKEY_ID)).expectNext(credential).verifyComplete();
    }
}
