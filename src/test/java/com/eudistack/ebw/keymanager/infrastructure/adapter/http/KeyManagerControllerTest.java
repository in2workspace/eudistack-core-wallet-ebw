package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import com.eudistack.ebw.keymanager.domain.exception.InvalidConsumerOriginException;
import com.eudistack.ebw.keymanager.domain.exception.InvalidKeyIdFormatException;
import com.eudistack.ebw.keymanager.domain.exception.TenantWalletProfileUnsupportedException;
import com.eudistack.ebw.keymanager.domain.exception.UnsupportedCredentialFormatException;
import com.eudistack.ebw.keymanager.domain.model.ConsumerOrigin;
import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.GenerateHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyId;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyResult;
import com.eudistack.ebw.keymanager.domain.model.JwkPublic;
import com.eudistack.ebw.keymanager.domain.model.JwsProof;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.model.SignHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.SignHolderKeyResult;
import com.eudistack.ebw.keymanager.domain.model.SignaturePurpose;
import com.eudistack.ebw.keymanager.domain.model.SigningType;
import com.eudistack.ebw.keymanager.domain.port.KeyManagerPort;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto.GenerateHolderKeyRequest;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto.SignHolderKeyRequest;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import com.eudistack.ebw.wallet.profile.domain.model.TenantWalletProfile;
import com.eudistack.ebw.wallet.profile.domain.model.WalletMode;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link KeyManagerController} — tenant wallet-profile gate on {@code /generate}, request parsing
 * (format, key id, consumer origin) and tenant propagation from the Reactor context. HTTP status mapping is covered
 * by {@code KeyManagerControllerIT} / {@code KeyManagerControllerIT_Sign}.
 */
@ExtendWith(MockitoExtension.class)
class KeyManagerControllerTest {

    private static final UUID USER_ID = UUID.randomUUID();
    private static final String TENANT = "sandbox";
    private static final Map<String, Object> JWK = Map.of("kty", "EC", "crv", "P-256", "x", "abc", "y", "def");

    @Mock private KeyManagerPort keyManagerPort;
    @Mock private WalletProfileQueryPort walletProfileQueryPort;

    private KeyManagerController controller;
    private JwtAuthenticationToken auth;

    @BeforeEach
    void setUp() {
        controller = new KeyManagerController(keyManagerPort, walletProfileQueryPort);
        auth = new JwtAuthenticationToken(USER_ID, "holder@example.com", List.of());
    }

    @Test
    void generate_serverDbTenant_returns201AndBuildsTheCommandFromContextAndRequest() {
        // Arrange
        var keyId = HolderKeyId.generate();
        when(walletProfileQueryPort.queryByCurrentTenant()).thenReturn(Mono.just(profile(WalletMode.SERVER, KeyManager.DB)));
        when(keyManagerPort.generateHolderKey(any())).thenReturn(Mono.just(new HolderKeyResult(keyId, new JwkPublic(JWK),
                new JwsProof("h.p.s", KeyAlgorithm.ES256), true)));

        // Act
        var result = controller.generate(generateRequest("dc+sd-jwt"), auth)
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TENANT));

        // Assert
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
                    assertThat(response.getBody().keyId()).isEqualTo(keyId.value().toString());
                    assertThat(response.getBody().jwsProof()).isEqualTo("h.p.s");
                    assertThat(response.getBody().warning()).isNull();
                })
                .verifyComplete();
        var command = ArgumentCaptor.forClass(GenerateHolderKeyCommand.class);
        verify(keyManagerPort).generateHolderKey(command.capture());
        assertThat(command.getValue().tenantId()).isEqualTo(TENANT);
        assertThat(command.getValue().holderId()).isEqualTo(USER_ID.toString());
        assertThat(command.getValue().format()).isEqualTo(CredentialFormat.SD_JWT_VC);
        assertThat(command.getValue().cNonce()).isEqualTo("nonce-1");
    }

    @Test
    void generate_existingKeyReused_addsTheWarning() {
        // Arrange
        when(walletProfileQueryPort.queryByCurrentTenant()).thenReturn(Mono.just(profile(WalletMode.SERVER, KeyManager.DB)));
        when(keyManagerPort.generateHolderKey(any())).thenReturn(Mono.just(new HolderKeyResult(HolderKeyId.generate(),
                new JwkPublic(JWK), new JwsProof("h.p.s", KeyAlgorithm.ES256), false)));

        // Act
        var result = controller.generate(generateRequest("jwt_vc_json"), auth)
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TENANT));

        // Assert
        StepVerifier.create(result)
                .assertNext(response -> assertThat(response.getBody().warning()).isEqualTo("existing_key_algorithm_used"))
                .verifyComplete();
    }

    @Test
    void generate_tenantNotServerDb_failsWithUnsupportedProfileWithoutGenerating() {
        // Arrange
        when(walletProfileQueryPort.queryByCurrentTenant())
                .thenReturn(Mono.just(profile(WalletMode.SERVER, KeyManager.HYBRID)));

        // Act
        var result = controller.generate(generateRequest("dc+sd-jwt"), auth)
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TENANT));

        // Assert
        StepVerifier.create(result).expectError(TenantWalletProfileUnsupportedException.class).verify();
        verifyNoInteractions(keyManagerPort);
    }

    @Test
    void generate_browserTenantWithoutContext_failsWithUnsupportedProfile() {
        // Arrange
        when(walletProfileQueryPort.queryByCurrentTenant()).thenReturn(Mono.just(profile(WalletMode.BROWSER, null)));

        // Act
        var result = controller.generate(generateRequest("dc+sd-jwt"), auth);

        // Assert
        StepVerifier.create(result).expectError(TenantWalletProfileUnsupportedException.class).verify();
    }

    @Test
    void generate_unknownFormat_failsBeforeQueryingTheProfile() {
        // Act + Assert
        assertThatThrownBy(() -> controller.generate(generateRequest("mso_mdoc"), auth))
                .isInstanceOf(UnsupportedCredentialFormatException.class);
        verifyNoInteractions(walletProfileQueryPort, keyManagerPort);
    }

    @Test
    void sign_validRequestWithOriginHeader_decodesInputAndPropagatesTenant() {
        // Arrange
        var keyId = UUID.randomUUID();
        var signingInput = "header.payload".getBytes(StandardCharsets.US_ASCII);
        when(keyManagerPort.signWithHolderKey(any()))
                .thenReturn(Mono.just(new SignHolderKeyResult("h.p.s", KeyAlgorithm.ES256, "jkt-1")));

        // Act
        var result = controller.sign(keyId.toString(), signRequest(signingInput), auth, " oid4vp_responder ")
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TENANT));

        // Assert
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                    assertThat(response.getBody().jws()).isEqualTo("h.p.s");
                    assertThat(response.getBody().algorithm()).isEqualTo("ES256");
                    assertThat(response.getBody().jkt()).isEqualTo("jkt-1");
                })
                .verifyComplete();
        var command = ArgumentCaptor.forClass(SignHolderKeyCommand.class);
        verify(keyManagerPort).signWithHolderKey(command.capture());
        assertThat(command.getValue().keyId().value()).isEqualTo(keyId);
        assertThat(command.getValue().tenantId()).isEqualTo(TENANT);
        assertThat(command.getValue().origin()).isEqualTo(ConsumerOrigin.OID4VP_RESPONDER);
        assertThat(command.getValue().signingInput()).isEqualTo(signingInput);
    }

    @Test
    void sign_withoutOriginHeader_defaultsToSystem() {
        // Arrange
        when(keyManagerPort.signWithHolderKey(any()))
                .thenReturn(Mono.just(new SignHolderKeyResult("h.p.s", KeyAlgorithm.ES256, "jkt-1")));

        // Act
        var result = controller.sign(UUID.randomUUID().toString(), signRequest(new byte[]{1}), auth, "  ")
                .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TENANT));

        // Assert
        StepVerifier.create(result).expectNextCount(1).verifyComplete();
        var command = ArgumentCaptor.forClass(SignHolderKeyCommand.class);
        verify(keyManagerPort).signWithHolderKey(command.capture());
        assertThat(command.getValue().origin()).isEqualTo(ConsumerOrigin.SYSTEM);
    }

    @Test
    void sign_unknownOriginHeader_failsWithInvalidConsumerOrigin() {
        // Act + Assert
        assertThatThrownBy(() -> controller.sign(UUID.randomUUID().toString(), signRequest(new byte[]{1}), auth,
                "browser")).isInstanceOf(InvalidConsumerOriginException.class);
        verifyNoInteractions(keyManagerPort);
    }

    @Test
    void sign_malformedKeyId_failsWithInvalidKeyIdFormat() {
        // Act + Assert
        assertThatThrownBy(() -> controller.sign("not-a-uuid", signRequest(new byte[]{1}), auth, null))
                .isInstanceOf(InvalidKeyIdFormatException.class);
        verifyNoInteractions(keyManagerPort);
    }

    private static GenerateHolderKeyRequest generateRequest(String format) {
        return new GenerateHolderKeyRequest("cred-1", format, List.of("ES256"), "https://issuer.example", "nonce-1");
    }

    private static SignHolderKeyRequest signRequest(byte[] signingInput) {
        return new SignHolderKeyRequest(SigningType.KB_JWT, SignaturePurpose.PRESENTATION,
                Base64.getUrlEncoder().withoutPadding().encodeToString(signingInput));
    }

    private static TenantWalletProfile profile(WalletMode mode, KeyManager keyManager) {
        return new TenantWalletProfile(TENANT, mode, keyManager, Instant.now(), Instant.now());
    }
}
