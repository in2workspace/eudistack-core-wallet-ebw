package com.eudistack.ebw.wallet.profile.application;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.wallet.profile.domain.exception.TenantUnknownException;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import com.eudistack.ebw.wallet.profile.domain.model.TenantWalletProfile;
import com.eudistack.ebw.wallet.profile.domain.model.WalletMode;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileReadPort;
import io.r2dbc.spi.R2dbcTimeoutException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.util.context.Context;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ReadWalletProfileUseCase}.
 *
 * <p>Covers:
 * <ul>
 *   <li>Missing TENANT_DOMAIN in context → {@code TenantUnknownException(TENANT_ABSENT_FROM_CONTEXT)}
 *   <li>Port returns {@code Mono.empty()} → {@code TenantUnknownException(PROFILE_NOT_SEEDED)}
 *   <li>R2DBC error pass-through (ES-04/ES-05)
 *   <li>Success pass-through
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class ReadWalletProfileUseCaseTest {

    @Mock
    private WalletProfileReadPort walletProfileReadPort;

    private ReadWalletProfileUseCase useCase;

    private static final Instant NOW = Instant.parse("2026-05-22T10:00:00Z");

    @BeforeEach
    void setUp() {
        useCase = new ReadWalletProfileUseCase(walletProfileReadPort);
    }

    @Test
    void queryByCurrentTenant_missingTenantDomainInContext_throwsTenantUnknownException() {
        StepVerifier.create(
                        useCase.queryByCurrentTenant()
                                .contextWrite(Context.empty()))
                .expectErrorSatisfies(error -> {
                    assertThat(error).isInstanceOf(TenantUnknownException.class);
                    TenantUnknownException ex = (TenantUnknownException) error;
                    assertThat(ex.getReason())
                            .isEqualTo(TenantUnknownException.Reason.TENANT_ABSENT_FROM_CONTEXT);
                })
                .verify();
    }

    @Test
    void queryByCurrentTenant_portReturnsEmpty_throwsTenantUnknownExceptionProfileNotSeeded() {
        when(walletProfileReadPort.findCurrent()).thenReturn(Mono.empty());

        StepVerifier.create(
                        useCase.queryByCurrentTenant()
                                .contextWrite(Context.of(ReactorContextKeys.TENANT_DOMAIN, "sandbox")))
                .expectErrorSatisfies(error -> {
                    assertThat(error).isInstanceOf(TenantUnknownException.class);
                    TenantUnknownException ex = (TenantUnknownException) error;
                    assertThat(ex.getReason())
                            .isEqualTo(TenantUnknownException.Reason.PROFILE_NOT_SEEDED);
                })
                .verify();
    }

    @Test
    void queryByCurrentTenant_r2dbcError_propagatesWithoutCapturing() {
        R2dbcTimeoutException r2dbcTimeout = new R2dbcTimeoutException("statement timeout", "08006");
        when(walletProfileReadPort.findCurrent()).thenReturn(Mono.error(r2dbcTimeout));

        StepVerifier.create(
                        useCase.queryByCurrentTenant()
                                .contextWrite(Context.of(ReactorContextKeys.TENANT_DOMAIN, "sandbox")))
                .expectErrorSatisfies(error -> assertThat(error)
                        .isSameAs(r2dbcTimeout)
                        .isInstanceOf(R2dbcTimeoutException.class))
                .verify();
    }

    @Test
    void queryByCurrentTenant_portReturnsProfile_emitsProfileUnchanged() {
        TenantWalletProfile profile =
                new TenantWalletProfile("sandbox", WalletMode.BROWSER, null, NOW, NOW);
        when(walletProfileReadPort.findCurrent()).thenReturn(Mono.just(profile));

        StepVerifier.create(
                        useCase.queryByCurrentTenant()
                                .contextWrite(Context.of(ReactorContextKeys.TENANT_DOMAIN, "sandbox")))
                .assertNext(result -> assertThat(result).isSameAs(profile))
                .verifyComplete();
    }

    @Test
    void queryByCurrentTenant_portReturnsServerProfile_emitsProfileUnchanged() {
        TenantWalletProfile profile =
                new TenantWalletProfile("kpmg", WalletMode.SERVER, KeyManager.HSM, NOW, NOW);
        when(walletProfileReadPort.findCurrent()).thenReturn(Mono.just(profile));

        StepVerifier.create(
                        useCase.queryByCurrentTenant()
                                .contextWrite(Context.of(ReactorContextKeys.TENANT_DOMAIN, "kpmg")))
                .assertNext(result -> {
                    assertThat(result.tenant()).isEqualTo("kpmg");
                    assertThat(result.walletMode()).isEqualTo(WalletMode.SERVER);
                    assertThat(result.keyManager()).isEqualTo(KeyManager.HSM);
                })
                .verifyComplete();
    }
}
