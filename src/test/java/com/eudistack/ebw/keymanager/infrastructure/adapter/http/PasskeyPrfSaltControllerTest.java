package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.domain.model.exception.InvalidSessionException;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import com.eudistack.ebw.keymanager.application.PrfSaltUseCase;
import com.eudistack.ebw.keymanager.domain.exception.PrfSaltNotFoundException;
import com.eudistack.ebw.keymanager.domain.exception.TenantWalletProfileUnsupportedException;
import com.eudistack.ebw.keymanager.domain.model.PrfSalt;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto.CreatePrfSaltRequest;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import com.eudistack.ebw.wallet.profile.domain.model.TenantWalletProfile;
import com.eudistack.ebw.wallet.profile.domain.model.WalletMode;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;

/**
 * Unit tests for {@link PasskeyPrfSaltController}: the custody gate, the passkey of the session and the shape of
 * the answer (EUD-11 openapi {@code /keys/passkey-prf/salts}).
 */
@ExtendWith(MockitoExtension.class)
class PasskeyPrfSaltControllerTest {

    private static final UUID USER_ID = UUID.randomUUID();
    private static final UUID PASSKEY_ID = UUID.randomUUID();
    private static final String TENANT = "cgcom";
    private static final String CREDENTIAL = "holder-1";
    private static final Map<String, Object> PUBLIC_JWK = Map.of("kty", "EC", "crv", "P-256", "x", "x1", "y", "y1");

    @Mock private PrfSaltUseCase prfSaltUseCase;
    @Mock private WalletProfileQueryPort walletProfileQueryPort;

    private PasskeyPrfSaltController controller;
    private JwtAuthenticationToken auth;

    @BeforeEach
    void setUp() {
        controller = new PasskeyPrfSaltController(prfSaltUseCase, walletProfileQueryPort);
        auth = new JwtAuthenticationToken(USER_ID, "holder@example.com", UUID.randomUUID(), PASSKEY_ID, List.of());
    }

    private static TenantWalletProfile profile(WalletMode mode, KeyManager keyManager) {
        return new TenantWalletProfile(TENANT, mode, keyManager, Instant.now(), Instant.now());
    }

    @Test
    void create_passkeyCustodyTenant_returns201WithSaltAndKdfButNoPublicKey() {
        // Arrange
        var salt = new byte[32];
        java.util.Arrays.fill(salt, (byte) 7);
        when(walletProfileQueryPort.queryByCurrentTenant())
                .thenReturn(Mono.just(profile(WalletMode.SERVER, KeyManager.PASSKEY_PRF)));
        when(prfSaltUseCase.createForPasskey(TENANT, USER_ID.toString(), PASSKEY_ID.toString(), CREDENTIAL))
                .thenReturn(Mono.just(new PrfSalt(CREDENTIAL, salt, PASSKEY_ID.toString(), null)));

        // Act
        var result = controller.create(new CreatePrfSaltRequest(CREDENTIAL), auth);

        // Assert
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
                    var body = response.getBody();
                    assertThat(body.credentialId()).isEqualTo(CREDENTIAL);
                    assertThat(body.prfSalt()).isEqualTo(Base64.getUrlEncoder().withoutPadding().encodeToString(salt));
                    assertThat(body.kdf().algorithm()).isEqualTo("HKDF-SHA-256");
                    assertThat(body.kdf().info()).isEqualTo("eudistack:passkey-prf:p256:v1");
                    assertThat(body.publicJwk()).isNull();
                })
                .verifyComplete();
    }

    @Test
    void get_attestationOfTheSessionPasskey_returnsSaltAndPublicKey() {
        // Arrange
        when(walletProfileQueryPort.queryByCurrentTenant())
                .thenReturn(Mono.just(profile(WalletMode.SERVER, KeyManager.PASSKEY_PRF)));
        when(prfSaltUseCase.getForPasskey(TENANT, USER_ID.toString(), PASSKEY_ID.toString(), CREDENTIAL))
                .thenReturn(Mono.just(new PrfSalt(CREDENTIAL, new byte[32], PASSKEY_ID.toString(), PUBLIC_JWK)));

        // Act
        var result = controller.get(CREDENTIAL, auth);

        // Assert
        StepVerifier.create(result)
                .assertNext(body -> {
                    assertThat(body.publicJwk()).isEqualTo(PUBLIC_JWK);
                    assertThat(body.prfSalt()).hasSize(43);
                })
                .verifyComplete();
    }

    @Test
    void get_useCaseSaysNotFound_propagatesIt() {
        // Arrange
        when(walletProfileQueryPort.queryByCurrentTenant())
                .thenReturn(Mono.just(profile(WalletMode.SERVER, KeyManager.PASSKEY_PRF)));
        when(prfSaltUseCase.getForPasskey(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.error(new PrfSaltNotFoundException(CREDENTIAL)));

        // Act
        var result = controller.get(CREDENTIAL, auth);

        // Assert
        StepVerifier.create(result).expectError(PrfSaltNotFoundException.class).verify();
    }

    @Test
    void create_serverCustodyTenant_failsWithUnsupportedCustodyModeWithoutCreatingASalt() {
        // Arrange
        when(walletProfileQueryPort.queryByCurrentTenant())
                .thenReturn(Mono.just(profile(WalletMode.SERVER, KeyManager.DB)));

        // Act
        var result = controller.create(new CreatePrfSaltRequest(CREDENTIAL), auth);

        // Assert
        StepVerifier.create(result).expectError(TenantWalletProfileUnsupportedException.class).verify();
        verifyNoInteractions(prfSaltUseCase);
    }

    @Test
    void get_browserTenant_failsWithUnsupportedCustodyMode() {
        // Arrange
        when(walletProfileQueryPort.queryByCurrentTenant())
                .thenReturn(Mono.just(profile(WalletMode.BROWSER, null)));

        // Act
        var result = controller.get(CREDENTIAL, auth);

        // Assert
        StepVerifier.create(result).expectError(TenantWalletProfileUnsupportedException.class).verify();
        verify(prfSaltUseCase, never()).getForPasskey(any(), any(), any(), any());
    }

    @Test
    void create_sessionWithoutPasskey_failsWithInvalidSessionAndCreatesNothing() {
        // Arrange
        var noPasskey = new JwtAuthenticationToken(USER_ID, "holder@example.com", UUID.randomUUID(), null, List.of());

        // Act + Assert
        assertThatThrownBy(() -> controller.create(new CreatePrfSaltRequest(CREDENTIAL), noPasskey))
                .isInstanceOf(InvalidSessionException.class);
        verifyNoInteractions(prfSaltUseCase);
    }

    @Test
    void get_sessionWithoutPasskey_failsWithInvalidSession() {
        // Arrange
        var noPasskey = new JwtAuthenticationToken(USER_ID, "holder@example.com", UUID.randomUUID(), null, List.of());

        // Act + Assert
        assertThatThrownBy(() -> controller.get(CREDENTIAL, noPasskey)).isInstanceOf(InvalidSessionException.class);
        verifyNoInteractions(prfSaltUseCase);
    }
}
