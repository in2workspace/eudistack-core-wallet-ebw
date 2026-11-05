package com.eudistack.ebw.keymanager.infrastructure.configuration;

import com.eudistack.ebw.domain.spi.AuditTrailPort;
import com.eudistack.ebw.keymanager.application.*;
import com.eudistack.ebw.keymanager.domain.model.SigningType;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyReadPort;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyWritePort;
import com.eudistack.ebw.keymanager.domain.port.KeyAuditPort;
import com.eudistack.ebw.keymanager.domain.port.KeyManagerPort;
import com.eudistack.ebw.keymanager.infrastructure.adapter.audit.KeyAuditTrailAdapter;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.PasskeyPrfKeyManagerExceptionHandler;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.PasskeyPrfSaltController;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.KeyManagerController;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.KeyManagerExceptionHandler;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.HolderKeyR2dbcAdapter;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.PrfSaltRepository;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.spring.SpringHolderKeyRepository;
import com.eudistack.ebw.keymanager.infrastructure.adapter.service.DbKeyManagerService;
import com.eudistack.ebw.keymanager.infrastructure.adapter.service.PasskeyPrfKeyManagerAdapter;
import com.eudistack.ebw.keymanager.infrastructure.health.KeyManagerHealthController;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.r2dbc.spi.ConnectionFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.r2dbc.core.DatabaseClient;

import java.util.Map;

/**
 * Spring configuration for the Key Manager bounded context.
 *
 * <p>Registers all beans for US-02 (key generation) and US-03 (server-side signing).
 * The {@code wallet.keymanager.enabled} property gate (already operativo from US-02)
 * is inherited by all signing beans via the same configuration class.</p>
 *
 * <p>Spec: EUDISTACK-119, EUDISTACK-407.</p>
 */
@Configuration
public class KeyManagerConfiguration {

    @Bean
    AlgorithmNegotiator algorithmNegotiator() {
        return new AlgorithmNegotiator();
    }

    @Bean
    HolderKeyFactory holderKeyFactory() {
        return new HolderKeyFactory();
    }

    @Bean
    IssuanceProofSigner issuanceProofSigner(ObjectMapper objectMapper) {
        return new IssuanceProofSigner(objectMapper);
    }

    @Bean
    HolderKeyR2dbcAdapter holderKeyR2dbcAdapter(SpringHolderKeyRepository repository,
                                                ObjectMapper objectMapper,
                                                DatabaseClient databaseClient) {
        return new HolderKeyR2dbcAdapter(repository, objectMapper, databaseClient);
    }

    /** The key events go to the audit API through the audit trail; with the publisher off it records nothing. */
    @Bean
    KeyAuditPort keyAuditPort(AuditTrailPort auditTrail) {
        return new KeyAuditTrailAdapter(auditTrail);
    }

    @Bean
    GenerateHolderKeyUseCase generateHolderKeyUseCase(AlgorithmNegotiator negotiator,
                                                      HolderKeyFactory factory,
                                                      HolderKeyWritePort writePort,
                                                      IssuanceProofSigner signer,
                                                      KeyAuditPort auditPort) {
        return new GenerateHolderKeyUseCase(negotiator, factory, writePort, signer, auditPort);
    }

    // --- US-03: Server-side signing beans ---

    @Bean
    KbJwtSigner kbJwtSigner() {
        return new KbJwtSigner();
    }

    @Bean
    VpEnvelopeSigner vpEnvelopeSigner() {
        return new VpEnvelopeSigner();
    }

    @Bean
    SignerSelector signerSelector(KbJwtSigner kbJwtSigner, VpEnvelopeSigner vpEnvelopeSigner) {
        Map<SigningType, JwsSigner> signers = Map.of(
                SigningType.KB_JWT, kbJwtSigner,
                SigningType.VP_ENVELOPE, vpEnvelopeSigner
        );
        return new SignerSelector(signers);
    }

    @Bean
    SignRejectionUniformDelay signRejectionUniformDelay(
            @Value("${keymanager.sign.opaque-rejection-delay-millis:"
                    + SignRejectionUniformDelay.DEFAULT_DELAY_MILLIS + "}") long delayMillis) {
        return new SignRejectionUniformDelay(delayMillis);
    }

    @Bean
    SignHolderKeyUseCase signHolderKeyUseCase(HolderKeyReadPort holderKeyReadPort,
                                              HolderKeyFactory holderKeyFactory,
                                              SignerSelector signerSelector,
                                              SignRejectionUniformDelay rejectionDelay,
                                              KeyAuditPort auditPort,
                                              WalletProfileQueryPort walletProfileQueryPort) {
        return new SignHolderKeyUseCase(holderKeyReadPort, holderKeyFactory, signerSelector,
                rejectionDelay, auditPort, walletProfileQueryPort);
    }

    @Bean
    KeyManagerPort keyManagerPort(GenerateHolderKeyUseCase generateUseCase,
                                  SignHolderKeyUseCase signUseCase) {
        return new DbKeyManagerService(generateUseCase, signUseCase);
    }

    // --- Passkey custody: the Wallet App signs; the service only keeps salt and public key ---

    @Bean
    PasskeyPrfKeyManagerAdapter passkeyPrfKeyManagerAdapter() {
        return new PasskeyPrfKeyManagerAdapter();
    }

    @Bean
    KeyManagerResolver keyManagerResolver(KeyManagerPort keyManagerPort,
                                          PasskeyPrfKeyManagerAdapter passkeyPrfKeyManagerAdapter) {
        return new KeyManagerResolver(keyManagerPort, passkeyPrfKeyManagerAdapter);
    }

    @Bean
    KeyManagerController keyManagerController(KeyManagerPort keyManagerPort,
                                              WalletProfileQueryPort walletProfileQueryPort) {
        return new KeyManagerController(keyManagerPort, walletProfileQueryPort);
    }

    @Bean
    KeyManagerExceptionHandler keyManagerExceptionHandler() {
        return new KeyManagerExceptionHandler();
    }

    @Bean
    PasskeyPrfKeyManagerExceptionHandler passkeyPrfKeyManagerExceptionHandler() {
        return new PasskeyPrfKeyManagerExceptionHandler();
    }

    @Bean
    KeyManagerHealthController keyManagerHealthController(ConnectionFactory connectionFactory) {
        return new KeyManagerHealthController(connectionFactory);
    }

    // --- Salt and public key of the attestations with passkey custody ---

    @Bean
    PrfSaltRepository prfSaltRepository(DatabaseClient databaseClient, ObjectMapper objectMapper) {
        return new PrfSaltRepository(databaseClient, objectMapper);
    }

    @Bean
    @Primary
    PrfSaltService prfSaltService(PrfSaltRepository prfSaltRepository, KeyAuditPort keyAuditPort) {
        return new PrfSaltService(prfSaltRepository, keyAuditPort);
    }

    @Bean
    PasskeyPrfSaltController passkeyPrfSaltController(PrfSaltUseCase prfSaltUseCase,
                                                      WalletProfileQueryPort walletProfileQueryPort) {
        return new PasskeyPrfSaltController(prfSaltUseCase, walletProfileQueryPort);
    }

    @Bean
    HolderKeyMaterialService holderKeyMaterialService(HolderKeyReadPort holderKeyReadPort,
                                                      HolderKeyWritePort holderKeyWritePort,
                                                      PrfSaltRepository prfSaltRepository,
                                                      KeyAuditPort keyAuditPort) {
        return new HolderKeyMaterialService(holderKeyReadPort, holderKeyWritePort, prfSaltRepository, keyAuditPort);
    }
}
