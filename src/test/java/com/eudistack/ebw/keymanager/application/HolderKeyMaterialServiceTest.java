package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.domain.model.CredentialFormat;
import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.model.CustodyMode;
import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.model.WalletCredential;
import com.eudistack.ebw.domain.model.exception.HolderKeyMismatchException;
import com.eudistack.ebw.domain.spi.HolderKeyMaterialPort.Binding;
import com.eudistack.ebw.keymanager.domain.model.HolderKey;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyId;
import com.eudistack.ebw.keymanager.domain.model.JwkPublic;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent.KeyAuditEventType;
import com.eudistack.ebw.keymanager.domain.model.PrfSalt;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyReadPort;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyWritePort;
import com.eudistack.ebw.keymanager.domain.port.KeyAuditPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
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

/**
 * Unit tests for {@link HolderKeyMaterialService}: an attestation must be bound to the key of its holder key
 * (compared by JWK thumbprint) and deleting it deletes that key's material (EUD-11 FR-05, FR-10, FR-16).
 */
@ExtendWith(MockitoExtension.class)
class HolderKeyMaterialServiceTest {

    private static final String TENANT = "sandbox";
    private static final UUID USER = UUID.randomUUID();
    private static final UUID PASSKEY = UUID.randomUUID();
    private static final UUID OTHER_PASSKEY = UUID.randomUUID();
    private static final HolderKeyId KEY_ID = HolderKeyId.generate();
    // 32 bytes, base64url: the size of a P-256 coordinate
    private static final String COORD_A = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private static final String COORD_B = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
    private static final Map<String, Object> KEY_A = Map.of("kty", "EC", "crv", "P-256", "x", COORD_A, "y", COORD_B);
    private static final Map<String, Object> KEY_A_WITH_EXTRA_MEMBERS =
            Map.of("kty", "EC", "crv", "P-256", "x", COORD_A, "y", COORD_B, "kid", "k1", "alg", "ES256");
    private static final Map<String, Object> KEY_B = Map.of("kty", "EC", "crv", "P-256", "x", COORD_B, "y", COORD_A);

    @Mock private HolderKeyReadPort holderKeyReadPort;
    @Mock private HolderKeyWritePort holderKeyWritePort;
    @Mock private PrfSaltPort prfSaltPort;
    @Mock private KeyAuditPort auditPort;

    private HolderKeyMaterialService service;

    @BeforeEach
    void setUp() {
        service = new HolderKeyMaterialService(holderKeyReadPort, holderKeyWritePort, prfSaltPort, auditPort);
        lenient().when(auditPort.emit(any())).thenReturn(Mono.empty());
    }

    private static <T> Mono<T> inTenant(Mono<T> mono) {
        return mono.contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, TENANT));
    }

    private static HolderKey holderKey(Map<String, Object> publicJwk) {
        return new HolderKey(KEY_ID, TENANT, USER.toString(), "app-credential-1",
                com.eudistack.ebw.keymanager.domain.model.CredentialFormat.SD_JWT_VC,
                KeyAlgorithm.ES256, new byte[]{1}, new JwkPublic(publicJwk), Instant.now(), null);
    }

    private static Binding serverBinding(Map<String, Object> cnf) {
        return new Binding(CustodyMode.SERVER, USER, PASSKEY, KEY_ID.value().toString(), cnf, null);
    }

    private static Binding passkeyBinding(Map<String, Object> cnf, Map<String, Object> holderPublicJwk) {
        return new Binding(CustodyMode.PASSKEY, USER, PASSKEY, "app-credential-1", cnf, holderPublicJwk);
    }

    private static WalletCredential credential(CustodyMode mode, String holderKeyId) {
        return new WalletCredential(UUID.randomUUID(), USER, "raw", CredentialFormat.DC_SD_JWT, "cfg", "kid", "Type",
                null, "iss", null, Instant.now(), null, CredentialStatus.VALID, Map.of(), holderKeyId, Instant.now(),
                Instant.now(), PASSKEY, mode != null, mode);
    }

    @Nested
    @DisplayName("verify with server custody")
    class VerifyServerCustody {

        @Test
        void verify_cnfIsTheKeyOfTheHolderKey_completes() {
            // Arrange
            when(holderKeyReadPort.findById(TENANT, USER.toString(), KEY_ID)).thenReturn(Mono.just(holderKey(KEY_A)));

            // Act
            var result = inTenant(service.verify(serverBinding(KEY_A_WITH_EXTRA_MEMBERS)));

            // Assert
            StepVerifier.create(result).verifyComplete();
        }

        @Test
        void verify_cnfIsAnotherKey_failsWithHolderKeyMismatch() {
            // Arrange
            when(holderKeyReadPort.findById(TENANT, USER.toString(), KEY_ID)).thenReturn(Mono.just(holderKey(KEY_A)));

            // Act
            var result = inTenant(service.verify(serverBinding(KEY_B)));

            // Assert
            StepVerifier.create(result).expectError(HolderKeyMismatchException.class).verify();
        }

        @Test
        void verify_holderKeyDoesNotExist_failsWithHolderKeyMismatch() {
            // Arrange
            when(holderKeyReadPort.findById(TENANT, USER.toString(), KEY_ID)).thenReturn(Mono.empty());

            // Act
            var result = inTenant(service.verify(serverBinding(KEY_A)));

            // Assert
            StepVerifier.create(result).expectError(HolderKeyMismatchException.class).verify();
        }

        @Test
        void verify_holderKeyIdIsNotAUuid_failsWithHolderKeyMismatch() {
            // Arrange
            var binding = new Binding(CustodyMode.SERVER, USER, PASSKEY, "not-a-uuid", KEY_A, null);

            // Act
            var result = inTenant(service.verify(binding));

            // Assert
            StepVerifier.create(result).expectError(HolderKeyMismatchException.class).verify();
            verify(holderKeyReadPort, never()).findById(anyString(), anyString(), any());
        }

        @Test
        void verify_attestationHasNoCnfKey_failsWithHolderKeyMismatch() {
            // Arrange
            when(holderKeyReadPort.findById(TENANT, USER.toString(), KEY_ID)).thenReturn(Mono.just(holderKey(KEY_A)));

            // Act
            var result = inTenant(service.verify(serverBinding(null)));

            // Assert
            StepVerifier.create(result).expectError(HolderKeyMismatchException.class).verify();
        }
    }

    @Nested
    @DisplayName("verify with passkey custody")
    class VerifyPasskeyCustody {

        @Test
        void verify_saltOfTheSessionPasskeyAndMatchingKey_completes() {
            // Arrange
            when(prfSaltPort.findBy(USER.toString(), "app-credential-1"))
                    .thenReturn(Mono.just(new PrfSalt("app-credential-1", new byte[32], PASSKEY.toString(), null)));

            // Act
            var result = service.verify(passkeyBinding(KEY_A, KEY_A_WITH_EXTRA_MEMBERS));

            // Assert
            StepVerifier.create(result).verifyComplete();
        }

        @Test
        void verify_cnfIsNotTheKeyTheAppDerived_failsWithHolderKeyMismatch() {
            // Arrange
            when(prfSaltPort.findBy(USER.toString(), "app-credential-1"))
                    .thenReturn(Mono.just(new PrfSalt("app-credential-1", new byte[32], PASSKEY.toString(), null)));

            // Act
            var result = service.verify(passkeyBinding(KEY_B, KEY_A));

            // Assert
            StepVerifier.create(result).expectError(HolderKeyMismatchException.class).verify();
        }

        @Test
        void verify_saltOfAnotherPasskey_failsWithHolderKeyMismatch() {
            // Arrange
            when(prfSaltPort.findBy(USER.toString(), "app-credential-1"))
                    .thenReturn(Mono.just(new PrfSalt("app-credential-1", new byte[32], OTHER_PASSKEY.toString(), null)));

            // Act
            var result = service.verify(passkeyBinding(KEY_A, KEY_A));

            // Assert
            StepVerifier.create(result).expectError(HolderKeyMismatchException.class).verify();
        }

        @Test
        void verify_noSaltForTheCredential_failsWithHolderKeyMismatch() {
            // Arrange
            when(prfSaltPort.findBy(USER.toString(), "app-credential-1")).thenReturn(Mono.empty());

            // Act
            var result = service.verify(passkeyBinding(KEY_A, KEY_A));

            // Assert
            StepVerifier.create(result).expectError(HolderKeyMismatchException.class).verify();
        }

        @Test
        void verify_appKeyCarriesThePrivateMember_failsWithHolderKeyMismatch() {
            // Arrange
            when(prfSaltPort.findBy(USER.toString(), "app-credential-1"))
                    .thenReturn(Mono.just(new PrfSalt("app-credential-1", new byte[32], PASSKEY.toString(), null)));
            var withPrivateMember = Map.<String, Object>of("kty", "EC", "crv", "P-256", "x", COORD_A, "y", COORD_B, "d", COORD_A);

            // Act
            var result = service.verify(passkeyBinding(KEY_A, withPrivateMember));

            // Assert
            StepVerifier.create(result).expectError(HolderKeyMismatchException.class).verify();
        }

        @Test
        void verify_appSendsNoPublicKey_failsWithHolderKeyMismatch() {
            // Arrange
            var binding = passkeyBinding(KEY_A, null);

            // Act
            var result = service.verify(binding);

            // Assert
            StepVerifier.create(result).expectError(HolderKeyMismatchException.class).verify();
            verify(prfSaltPort, never()).findBy(anyString(), anyString());
        }
    }

    @Nested
    @DisplayName("keepPublicKey")
    class KeepPublicKey {

        @Test
        void keepPublicKey_passkeyCustody_storesTheKeyInTheRowOfTheSessionPasskey() {
            // Arrange
            when(prfSaltPort.setPublicJwk(USER.toString(), "app-credential-1", PASSKEY.toString(), KEY_A))
                    .thenReturn(Mono.just(true));

            // Act
            var result = service.keepPublicKey(passkeyBinding(KEY_A, KEY_A));

            // Assert
            StepVerifier.create(result).verifyComplete();
        }

        @Test
        void keepPublicKey_keyCarriesThePrivateMember_failsWithHolderKeyMismatchAndStoresNothing() {
            // Arrange
            var withPrivateMember = Map.<String, Object>of("kty", "EC", "crv", "P-256", "x", COORD_A, "y", COORD_B, "d", COORD_A);

            // Act
            var result = service.keepPublicKey(passkeyBinding(KEY_A, withPrivateMember));

            // Assert
            StepVerifier.create(result).expectError(HolderKeyMismatchException.class).verify();
            verify(prfSaltPort, never()).setPublicJwk(any(), any(), any(), any());
        }

        @Test
        void keepPublicKey_keyHasExtraMembers_storesOnlyKtyCrvXAndY() {
            // Arrange
            when(prfSaltPort.setPublicJwk(USER.toString(), "app-credential-1", PASSKEY.toString(), KEY_A))
                    .thenReturn(Mono.just(true));

            // Act
            var result = service.keepPublicKey(passkeyBinding(KEY_A, KEY_A_WITH_EXTRA_MEMBERS));

            // Assert
            StepVerifier.create(result).verifyComplete();
            verify(prfSaltPort).setPublicJwk(USER.toString(), "app-credential-1", PASSKEY.toString(), KEY_A);
        }

        @Test
        void keepPublicKey_keyIsNotP256_failsWithHolderKeyMismatch() {
            // Arrange
            var otherCurve = Map.<String, Object>of("kty", "EC", "crv", "P-384", "x", COORD_A, "y", COORD_B);

            // Act
            var result = service.keepPublicKey(passkeyBinding(KEY_A, otherCurve));

            // Assert
            StepVerifier.create(result).expectError(HolderKeyMismatchException.class).verify();
        }

        @Test
        void keepPublicKey_coordinateIsNotThirtyTwoBytes_failsWithHolderKeyMismatch() {
            // Arrange
            var shortCoordinate = Map.<String, Object>of("kty", "EC", "crv", "P-256", "x", "xa", "y", COORD_B);

            // Act
            var result = service.keepPublicKey(passkeyBinding(KEY_A, shortCoordinate));

            // Assert
            StepVerifier.create(result).expectError(HolderKeyMismatchException.class).verify();
        }

        @Test
        void keepPublicKey_rowNotUpdated_failsWithHolderKeyMismatch() {
            // Arrange
            when(prfSaltPort.setPublicJwk(any(), any(), any(), any())).thenReturn(Mono.just(false));

            // Act
            var result = service.keepPublicKey(passkeyBinding(KEY_A, KEY_A));

            // Assert
            StepVerifier.create(result).expectError(HolderKeyMismatchException.class).verify();
        }

        @Test
        void keepPublicKey_serverCustody_doesNothing() {
            // Arrange
            var binding = serverBinding(KEY_A);

            // Act
            var result = service.keepPublicKey(binding);

            // Assert
            StepVerifier.create(result).verifyComplete();
            verify(prfSaltPort, never()).setPublicJwk(any(), any(), any(), any());
        }
    }

    @Nested
    @DisplayName("delete")
    class Delete {

        @Test
        void delete_serverCustody_deletesTheKeyAndAuditsKeyDeleted() {
            // Arrange
            var credential = credential(CustodyMode.SERVER, KEY_ID.value().toString());
            when(holderKeyReadPort.findById(TENANT, USER.toString(), KEY_ID)).thenReturn(Mono.just(holderKey(KEY_A)));
            when(holderKeyWritePort.deleteById(TENANT, USER.toString(), KEY_ID)).thenReturn(Mono.just(true));

            // Act
            var result = inTenant(service.delete(credential));

            // Assert
            StepVerifier.create(result).verifyComplete();
            var event = captureEvent();
            assertThat(event.type()).isEqualTo(KeyAuditEventType.KEY_DELETED);
            assertThat(event.custodyMode()).isEqualTo(CustodyMode.SERVER);
            assertThat(event.credentialId()).isEqualTo("app-credential-1");
            assertThat(event.keyId()).isEqualTo(KEY_ID.value().toString());
        }

        @Test
        void delete_passkeyCustody_deletesTheSaltAndAuditsSaltDeleted() {
            // Arrange
            var credential = credential(CustodyMode.PASSKEY, "app-credential-1");
            when(prfSaltPort.delete(USER.toString(), "app-credential-1")).thenReturn(Mono.just(true));

            // Act
            var result = inTenant(service.delete(credential));

            // Assert
            StepVerifier.create(result).verifyComplete();
            var event = captureEvent();
            assertThat(event.type()).isEqualTo(KeyAuditEventType.SALT_DELETED);
            assertThat(event.custodyMode()).isEqualTo(CustodyMode.PASSKEY);
            assertThat(event.credentialId()).isEqualTo("app-credential-1");
        }

        @Test
        void delete_noRowDeleted_auditsNothing() {
            // Arrange
            var credential = credential(CustodyMode.PASSKEY, "app-credential-1");
            when(prfSaltPort.delete(USER.toString(), "app-credential-1")).thenReturn(Mono.just(false));

            // Act
            var result = inTenant(service.delete(credential));

            // Assert
            StepVerifier.create(result).verifyComplete();
            verify(auditPort, never()).emit(any());
        }

        @Test
        void delete_attestationWithoutCustodyMode_doesNothing() {
            // Arrange
            var credential = credential(null, "legacy-key");

            // Act
            var result = inTenant(service.delete(credential));

            // Assert
            StepVerifier.create(result).verifyComplete();
            verify(holderKeyWritePort, never()).deleteById(anyString(), anyString(), any());
            verify(prfSaltPort, never()).delete(anyString(), anyString());
        }

        @Test
        void delete_auditChannelFails_stillCompletes() {
            // Arrange
            var credential = credential(CustodyMode.PASSKEY, "app-credential-1");
            when(prfSaltPort.delete(eq(USER.toString()), anyString())).thenReturn(Mono.just(true));
            when(auditPort.emit(any())).thenReturn(Mono.error(new IllegalStateException("audit down")));

            // Act
            var result = inTenant(service.delete(credential));

            // Assert
            StepVerifier.create(result).verifyComplete();
        }

        private KeyAuditEvent captureEvent() {
            var captor = ArgumentCaptor.forClass(KeyAuditEvent.class);
            verify(auditPort).emit(captor.capture());
            return captor.getValue();
        }
    }
}
