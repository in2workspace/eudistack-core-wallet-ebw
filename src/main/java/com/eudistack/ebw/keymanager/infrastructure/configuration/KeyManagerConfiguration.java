package com.eudistack.ebw.keymanager.infrastructure.configuration;

import com.eudistack.ebw.keymanager.application.*;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent;
import com.eudistack.ebw.keymanager.domain.model.SigningType;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyReadPort;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyWritePort;
import com.eudistack.ebw.keymanager.domain.port.KeyAuditPort;
import com.eudistack.ebw.keymanager.domain.port.KeyManagerPort;
import com.eudistack.ebw.keymanager.infrastructure.adapter.audit.KeyAuditCloudWatchAdapter;
import com.eudistack.ebw.keymanager.domain.port.WrappedKeyHandleRepository;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.HybridKeyManagerController;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.HybridKeyManagerExceptionHandler;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.HybridOnboardingController;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.KeyManagerController;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.KeyManagerExceptionHandler;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.HolderKeyR2dbcAdapter;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.HybridWrappedKeyHandleR2dbcAdapter;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.PrfSaltRepository;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.spring.SpringHolderKeyRepository;
import com.eudistack.ebw.keymanager.infrastructure.adapter.service.DbKeyManagerService;
import com.eudistack.ebw.keymanager.infrastructure.adapter.service.HybridKeyManagerAdapter;
import com.eudistack.ebw.keymanager.infrastructure.health.HybridHealthContributor;
import com.eudistack.ebw.keymanager.infrastructure.health.KeyManagerHealthController;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.r2dbc.spi.ConnectionFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.Mono;

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

    @Bean
    @ConditionalOnProperty(name = "keymanager.audit.enabled", havingValue = "true")
    KeyAuditPort keyAuditCloudWatchAdapter(
            @Value("${keymanager.audit.log-group-name}") String logGroupName,
            ObjectMapper objectMapper) {
        return new KeyAuditCloudWatchAdapter(logGroupName, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean(KeyAuditPort.class)
    KeyAuditPort keyAuditNoOpPort() {
        return (KeyAuditEvent event) -> Mono.empty();
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

    // --- EUDISTACK-533 US-01: Hybrid adapter + per-tenant resolver ---

    @Bean
    HybridKeyManagerAdapter hybridKeyManagerAdapter() {
        return new HybridKeyManagerAdapter();
    }

    @Bean
    KeyManagerResolver keyManagerResolver(KeyManagerPort keyManagerPort,
                                          HybridKeyManagerAdapter hybridKeyManagerAdapter) {
        return new KeyManagerResolver(keyManagerPort, hybridKeyManagerAdapter);
    }

    @Bean
    KeyManagerController keyManagerController(KeyManagerPort keyManagerPort,
                                              WalletProfileQueryPort walletProfileQueryPort) {
        return new KeyManagerController(keyManagerPort, walletProfileQueryPort);
    }

    @Bean
    HybridKeyManagerController hybridKeyManagerController(
            HybridKeyManagerAdapter hybridKeyManagerAdapter,
            WalletProfileQueryPort walletProfileQueryPort) {
        return new HybridKeyManagerController(hybridKeyManagerAdapter, walletProfileQueryPort);
    }

    @Bean
    KeyManagerExceptionHandler keyManagerExceptionHandler() {
        return new KeyManagerExceptionHandler();
    }

    @Bean
    HybridKeyManagerExceptionHandler hybridKeyManagerExceptionHandler() {
        return new HybridKeyManagerExceptionHandler();
    }

    @Bean
    KeyManagerHealthController keyManagerHealthController(ConnectionFactory connectionFactory) {
        return new KeyManagerHealthController(connectionFactory);
    }

    // --- EUDISTACK-534 US-02: Hybrid onboarding beans ---

    @Bean
    HybridWrappedKeyHandleR2dbcAdapter hybridWrappedKeyHandleR2dbcAdapter(
            DatabaseClient databaseClient) {
        return new HybridWrappedKeyHandleR2dbcAdapter(databaseClient);
    }

    @Bean
    EnrollHolderUseCase enrollHolderUseCase(PrfSaltUseCase prfSaltUseCase,
                                            WrappedKeyHandleRepository wrappedKeyHandleRepository) {
        return new EnrollHolderUseCase(prfSaltUseCase, wrappedKeyHandleRepository);
    }

    @Bean
    HybridOnboardingController hybridOnboardingController(
            EnrollHolderUseCase enrollHolderUseCase,
            WalletProfileQueryPort walletProfileQueryPort,
            ObjectMapper objectMapper) {
        return new HybridOnboardingController(enrollHolderUseCase, walletProfileQueryPort, objectMapper);
    }

    // --- EUDISTACK-537 US-05: PRF salt persistence, use case + health indicator ---

    @Bean
    HybridHealthContributor hybridHealthContributor(DatabaseClient databaseClient) {
        return new HybridHealthContributor(databaseClient);
    }

    @Bean
    PrfSaltRepository prfSaltRepository(DatabaseClient databaseClient) {
        return new PrfSaltRepository(databaseClient);
    }

    @Bean
    @Primary
    PrfSaltService prfSaltService(PrfSaltRepository prfSaltRepository) {
        return new PrfSaltService(prfSaltRepository);
    }
}