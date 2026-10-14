package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import com.eudistack.ebw.keymanager.application.EnrollHolderUseCase;
import com.eudistack.ebw.keymanager.domain.exception.InvalidCommitException;
import com.eudistack.ebw.keymanager.domain.exception.PrfUnsupportedException;
import com.eudistack.ebw.keymanager.domain.exception.TenantWalletProfileUnsupportedException;
import com.eudistack.ebw.keymanager.domain.model.EnrollHolderCommitRequest;
import com.eudistack.ebw.keymanager.domain.model.EnrollHolderCommitResponse;
import com.eudistack.ebw.keymanager.domain.model.EnrollHolderInitRequest;
import com.eudistack.ebw.keymanager.domain.model.EnrollHolderInitResponse;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto.BlockOnboardingRequest;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import com.eudistack.ebw.wallet.profile.domain.model.TenantWalletProfile;
import com.eudistack.ebw.wallet.profile.domain.model.WalletMode;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

@ExtendWith(MockitoExtension.class)
class PasskeyPrfOnboardingControllerTest {

    private static final String TENANT = "sandbox";
    private static final UUID USER_ID = UUID.randomUUID();

    @Mock private EnrollHolderUseCase enrollHolderUseCase;
    @Mock private WalletProfileQueryPort walletProfileQueryPort;

    private PasskeyPrfOnboardingController controller;
    private JwtAuthenticationToken auth;

    @BeforeEach
    void setUp() {
        controller = new PasskeyPrfOnboardingController(
                enrollHolderUseCase, walletProfileQueryPort, new ObjectMapper());
        auth = new JwtAuthenticationToken(USER_ID, "holder@example.com", UUID.randomUUID(), UUID.randomUUID(), List.of());
    }

    private void givenProfile(WalletMode mode, KeyManager keyManager) {
        when(walletProfileQueryPort.queryByCurrentTenant()).thenReturn(Mono.just(
                new TenantWalletProfile(TENANT, mode, keyManager, Instant.now(), Instant.now())));
    }

    private static EnrollHolderCommitRequest commitRequest(String cnfJwk) {
        return new EnrollHolderCommitRequest("cred-1", "blob", "iv0123456789abcd", "tag0123456789abcdefghi",
                "AES-256-GCM", 1, cnfJwk);
    }

    @Test
    void init_passkeyPrfTenant_returns200WithUseCaseResponse() {
        givenProfile(WalletMode.SERVER, KeyManager.PASSKEY_PRF);
        EnrollHolderInitRequest request = new EnrollHolderInitRequest("cred-1", "vc+sd-jwt");
        EnrollHolderInitResponse response = new EnrollHolderInitResponse("salt", "{}", "SD-JWT");
        when(enrollHolderUseCase.init(TENANT, USER_ID.toString(), request)).thenReturn(Mono.just(response));

        StepVerifier.create(controller.init(request, auth)
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TENANT)))
                .assertNext(entity -> {
                    assertThat(entity.getStatusCode()).isEqualTo(HttpStatus.OK);
                    assertThat(entity.getBody()).isEqualTo(response);
                })
                .verifyComplete();
    }

    @Test
    void init_dbTenant_isRejectedBeforeReachingTheUseCase() {
        givenProfile(WalletMode.SERVER, KeyManager.DB);

        StepVerifier.create(controller.init(new EnrollHolderInitRequest("cred-1", "vc+sd-jwt"), auth)
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TENANT)))
                .expectError(TenantWalletProfileUnsupportedException.class)
                .verify();

        verify(enrollHolderUseCase, never()).init(any(), any(), any());
    }

    @Test
    void init_browserTenant_isRejected() {
        givenProfile(WalletMode.BROWSER, null);

        StepVerifier.create(controller.init(new EnrollHolderInitRequest("cred-1", "vc+sd-jwt"), auth))
                .expectError(TenantWalletProfileUnsupportedException.class)
                .verify();
    }

    @Test
    void commit_newHandle_returns201() {
        givenProfile(WalletMode.SERVER, KeyManager.PASSKEY_PRF);
        EnrollHolderCommitRequest request = commitRequest("{\"kty\":\"EC\"}");
        when(enrollHolderUseCase.commit(TENANT, USER_ID.toString(), request))
                .thenReturn(Mono.just(new EnrollHolderCommitResponse("cred-1", false)));

        StepVerifier.create(controller.commit(request, auth)
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TENANT)))
                .assertNext(entity -> assertThat(entity.getStatusCode()).isEqualTo(HttpStatus.CREATED))
                .verifyComplete();
    }

    @Test
    void commit_replay_returns200() {
        givenProfile(WalletMode.SERVER, KeyManager.PASSKEY_PRF);
        EnrollHolderCommitRequest request = commitRequest("{\"kty\":\"EC\"}");
        when(enrollHolderUseCase.commit(TENANT, USER_ID.toString(), request))
                .thenReturn(Mono.just(new EnrollHolderCommitResponse("cred-1", true)));

        StepVerifier.create(controller.commit(request, auth)
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TENANT)))
                .assertNext(entity -> assertThat(entity.getStatusCode()).isEqualTo(HttpStatus.OK))
                .verifyComplete();
    }

    @Test
    void commit_cnfJwkWithPrivateKeyParameter_isRejectedBeforeAnyLookup() {
        StepVerifier.create(controller.commit(commitRequest("{\"kty\":\"EC\",\"d\":\"secret\"}"), auth))
                .expectError(InvalidCommitException.class)
                .verify();

        verify(walletProfileQueryPort, never()).queryByCurrentTenant();
    }

    @Test
    void commit_cnfJwkNotJson_isRejected() {
        StepVerifier.create(controller.commit(commitRequest("not-json"), auth))
                .expectErrorMatches(ex -> ex instanceof InvalidCommitException
                        && ex.getMessage().contains("not valid JSON"))
                .verify();
    }

    @Test
    void block_passkeyPrfTenant_recordsAuditAndFailsWithPrfUnsupported() {
        givenProfile(WalletMode.SERVER, KeyManager.PASSKEY_PRF);
        when(enrollHolderUseCase.recordPrfUnsupported(TENANT, USER_ID.toString())).thenReturn(Mono.empty());

        StepVerifier.create(controller.block(new BlockOnboardingRequest("cred-1", "corr-1"), auth)
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TENANT)))
                .expectError(PrfUnsupportedException.class)
                .verify();

        verify(enrollHolderUseCase).recordPrfUnsupported(TENANT, USER_ID.toString());
    }

    @Test
    void block_auditFailure_isSwallowedAndStillFailsWithPrfUnsupported() {
        givenProfile(WalletMode.SERVER, KeyManager.PASSKEY_PRF);
        when(enrollHolderUseCase.recordPrfUnsupported(TENANT, USER_ID.toString()))
                .thenReturn(Mono.error(new IllegalStateException("cloudwatch down")));

        StepVerifier.create(controller.block(new BlockOnboardingRequest("cred-1", "corr-1"), auth)
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TENANT)))
                .expectError(PrfUnsupportedException.class)
                .verify();
    }
}
