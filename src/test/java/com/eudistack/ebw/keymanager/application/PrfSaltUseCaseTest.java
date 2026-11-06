package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.exception.PrfSaltNotFoundException;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent.KeyAuditEventType;
import com.eudistack.ebw.keymanager.domain.model.PrfSalt;
import com.eudistack.ebw.keymanager.domain.port.KeyAuditPort;
import com.eudistack.ebw.domain.model.CustodyMode;
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

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PrfSaltService}: the salt of an attestation is created for, and only given to, the
 * passkey of the session; any other passkey is answered as if the salt did not exist (EUD-11 FR-13, FR-14).
 */
@ExtendWith(MockitoExtension.class)
class PrfSaltUseCaseTest {

    private static final String TENANT = "cgcom";
    private static final String HOLDER = "11111111-1111-1111-1111-111111111111";
    private static final String PASSKEY = "22222222-2222-2222-2222-222222222222";
    private static final String OTHER_PASSKEY = "33333333-3333-3333-3333-333333333333";
    private static final String CREDENTIAL = "holder-1";
    private static final Map<String, Object> PUBLIC_JWK = Map.of("kty", "EC", "crv", "P-256", "x", "x1", "y", "y1");

    @Mock private PrfSaltPort prfSaltPort;
    @Mock private KeyAuditPort auditPort;

    private PrfSaltService service;

    @BeforeEach
    void setUp() {
        service = new PrfSaltService(prfSaltPort, auditPort);
        org.mockito.Mockito.lenient().when(auditPort.emit(any())).thenReturn(Mono.empty());
    }

    private KeyAuditEvent emittedEvent() {
        var captor = ArgumentCaptor.forClass(KeyAuditEvent.class);
        verify(auditPort).emit(captor.capture());
        return captor.getValue();
    }

    @Nested
    @DisplayName("createForPasskey")
    class CreateForPasskey {

        @Test
        void createForPasskey_newCredential_insertsA32ByteSaltBoundToThePasskeyAndAuditsSaltCreated() {
            // Arrange
            var created = new PrfSalt(CREDENTIAL, new byte[32], PASSKEY, null);
            when(prfSaltPort.findBy(HOLDER, CREDENTIAL)).thenReturn(Mono.empty(), Mono.just(created));
            when(prfSaltPort.insert(eq(HOLDER), eq(CREDENTIAL), eq(PASSKEY), any())).thenReturn(Mono.just(true));

            // Act
            var result = service.createForPasskey(TENANT, HOLDER, PASSKEY, CREDENTIAL);

            // Assert
            StepVerifier.create(result).expectNext(created).verifyComplete();
            var salt = ArgumentCaptor.forClass(byte[].class);
            verify(prfSaltPort).insert(eq(HOLDER), eq(CREDENTIAL), eq(PASSKEY), salt.capture());
            assertThat(salt.getValue()).hasSize(32);
            var event = emittedEvent();
            assertThat(event.type()).isEqualTo(KeyAuditEventType.SALT_CREATED);
            assertThat(event.custodyMode()).isEqualTo(CustodyMode.PASSKEY);
            assertThat(event.credentialId()).isEqualTo(CREDENTIAL);
        }

        @Test
        void createForPasskey_samePasskeyAsksAgain_returnsTheSameSaltWithoutInsertingAndAuditsDelivery() {
            // Arrange
            var existing = new PrfSalt(CREDENTIAL, new byte[32], PASSKEY, null);
            when(prfSaltPort.findBy(HOLDER, CREDENTIAL)).thenReturn(Mono.just(existing));

            // Act
            var result = service.createForPasskey(TENANT, HOLDER, PASSKEY, CREDENTIAL);

            // Assert
            StepVerifier.create(result).expectNext(existing).verifyComplete();
            verify(prfSaltPort, never()).insert(anyString(), anyString(), anyString(), any());
            assertThat(emittedEvent().type()).isEqualTo(KeyAuditEventType.SALT_DELIVERED);
        }

        @Test
        void createForPasskey_concurrentCreationWonByAnother_returnsTheWinnersSaltAsDelivered() {
            // Arrange
            var winner = new PrfSalt(CREDENTIAL, new byte[32], PASSKEY, null);
            when(prfSaltPort.findBy(HOLDER, CREDENTIAL)).thenReturn(Mono.empty(), Mono.just(winner));
            when(prfSaltPort.insert(eq(HOLDER), eq(CREDENTIAL), eq(PASSKEY), any())).thenReturn(Mono.just(false));

            // Act
            var result = service.createForPasskey(TENANT, HOLDER, PASSKEY, CREDENTIAL);

            // Assert
            StepVerifier.create(result).expectNext(winner).verifyComplete();
            assertThat(emittedEvent().type()).isEqualTo(KeyAuditEventType.SALT_DELIVERED);
        }

        @Test
        void createForPasskey_credentialOfAnotherPasskey_failsAsNotFoundAndAuditsTheDenial() {
            // Arrange
            when(prfSaltPort.findBy(HOLDER, CREDENTIAL)).thenReturn(Mono.just(new PrfSalt(CREDENTIAL, new byte[32], OTHER_PASSKEY, null)));

            // Act
            var result = service.createForPasskey(TENANT, HOLDER, PASSKEY, CREDENTIAL);

            // Assert
            StepVerifier.create(result).expectError(PrfSaltNotFoundException.class).verify();
            var event = emittedEvent();
            assertThat(event.type()).isEqualTo(KeyAuditEventType.SALT_DELIVERY_DENIED);
            assertThat(event.reason()).isEqualTo(PrfSaltService.REASON_OTHER_PASSKEY);
        }

        @Test
        void createForPasskey_saltWhosePasskeyWasDeleted_failsAsNotFound() {
            // Arrange
            when(prfSaltPort.findBy(HOLDER, CREDENTIAL)).thenReturn(Mono.just(new PrfSalt(CREDENTIAL, new byte[32], null, null)));

            // Act
            var result = service.createForPasskey(TENANT, HOLDER, PASSKEY, CREDENTIAL);

            // Assert
            StepVerifier.create(result).expectError(PrfSaltNotFoundException.class).verify();
        }

        @Test
        void createForPasskey_auditChannelFails_stillReturnsTheSalt() {
            // Arrange
            var existing = new PrfSalt(CREDENTIAL, new byte[32], PASSKEY, null);
            when(prfSaltPort.findBy(HOLDER, CREDENTIAL)).thenReturn(Mono.just(existing));
            when(auditPort.emit(any())).thenReturn(Mono.error(new IllegalStateException("audit down")));

            // Act
            var result = service.createForPasskey(TENANT, HOLDER, PASSKEY, CREDENTIAL);

            // Assert
            StepVerifier.create(result).expectNext(existing).verifyComplete();
        }
    }

    @Nested
    @DisplayName("getForPasskey")
    class GetForPasskey {

        @Test
        void getForPasskey_saltOfThePasskeyWithPublicKey_returnsItAndAuditsDelivery() {
            // Arrange
            var stored = new PrfSalt(CREDENTIAL, new byte[32], PASSKEY, PUBLIC_JWK);
            when(prfSaltPort.findBy(HOLDER, CREDENTIAL)).thenReturn(Mono.just(stored));

            // Act
            var result = service.getForPasskey(TENANT, HOLDER, PASSKEY, CREDENTIAL);

            // Assert
            StepVerifier.create(result).expectNext(stored).verifyComplete();
            assertThat(emittedEvent().type()).isEqualTo(KeyAuditEventType.SALT_DELIVERED);
        }

        @Test
        void getForPasskey_attestationOfAnotherPasskey_failsAsNotFoundAndAuditsTheDenial() {
            // Arrange
            when(prfSaltPort.findBy(HOLDER, CREDENTIAL)).thenReturn(Mono.just(new PrfSalt(CREDENTIAL, new byte[32], OTHER_PASSKEY, PUBLIC_JWK)));

            // Act
            var result = service.getForPasskey(TENANT, HOLDER, PASSKEY, CREDENTIAL);

            // Assert
            StepVerifier.create(result).expectError(PrfSaltNotFoundException.class).verify();
            var event = emittedEvent();
            assertThat(event.type()).isEqualTo(KeyAuditEventType.SALT_DELIVERY_DENIED);
            assertThat(event.reason()).isEqualTo(PrfSaltService.REASON_OTHER_PASSKEY);
        }

        @Test
        void getForPasskey_attestationWithoutPublicKeyYet_failsAsNotFound() {
            // Arrange
            when(prfSaltPort.findBy(HOLDER, CREDENTIAL)).thenReturn(Mono.just(new PrfSalt(CREDENTIAL, new byte[32], PASSKEY, null)));

            // Act
            var result = service.getForPasskey(TENANT, HOLDER, PASSKEY, CREDENTIAL);

            // Assert
            StepVerifier.create(result).expectError(PrfSaltNotFoundException.class).verify();
            assertThat(emittedEvent().reason()).isEqualTo(PrfSaltService.REASON_NO_PUBLIC_KEY);
        }

        @Test
        void getForPasskey_unknownAttestation_failsAsNotFoundAndAuditsTheDenial() {
            // Arrange
            when(prfSaltPort.findBy(HOLDER, CREDENTIAL)).thenReturn(Mono.empty());

            // Act
            var result = service.getForPasskey(TENANT, HOLDER, PASSKEY, CREDENTIAL);

            // Assert
            StepVerifier.create(result).expectError(PrfSaltNotFoundException.class).verify();
            assertThat(emittedEvent().reason()).isEqualTo(PrfSaltService.REASON_NOT_FOUND);
        }

        @Test
        void getForPasskey_denial_neverCarriesTheSaltInTheAuditEvent() {
            // Arrange
            var salt = new byte[]{42, 42, 42, 42};
            when(prfSaltPort.findBy(HOLDER, CREDENTIAL)).thenReturn(Mono.just(new PrfSalt(CREDENTIAL, salt, OTHER_PASSKEY, PUBLIC_JWK)));

            // Act
            StepVerifier.create(service.getForPasskey(TENANT, HOLDER, PASSKEY, CREDENTIAL))
                    .expectError(PrfSaltNotFoundException.class).verify();

            // Assert
            assertThat(emittedEvent().toString()).doesNotContain("42, 42");
        }
    }
}
