package com.eudistack.ebw.keymanager.infrastructure.configuration;

import com.eudistack.ebw.keymanager.application.AlgorithmNegotiator;
import com.eudistack.ebw.keymanager.application.GenerateHolderKeyUseCase;
import com.eudistack.ebw.keymanager.application.HolderKeyFactory;
import com.eudistack.ebw.keymanager.application.IssuanceProofSigner;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyReadPort;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyWritePort;
import com.eudistack.ebw.keymanager.domain.port.KeyAuditPort;
import com.eudistack.ebw.keymanager.domain.port.KeyManagerPort;
import com.eudistack.ebw.keymanager.infrastructure.adapter.audit.KeyAuditCloudWatchAdapter;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.KeyManagerController;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.KeyManagerExceptionHandler;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.HolderKeyR2dbcAdapter;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.spring.SpringHolderKeyRepository;
import com.eudistack.ebw.keymanager.infrastructure.adapter.service.DbKeyManagerService;
import com.eudistack.ebw.keymanager.infrastructure.health.KeyManagerHealthController;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.r2dbc.spi.ConnectionFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.Mono;

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
    HolderKeyReadPort holderKeyReadPort(HolderKeyR2dbcAdapter adapter) {
        return adapter;
    }

    @Bean
    HolderKeyWritePort holderKeyWritePort(HolderKeyR2dbcAdapter adapter) {
        return adapter;
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

    @Bean
    KeyManagerPort keyManagerPort(GenerateHolderKeyUseCase useCase) {
        return new DbKeyManagerService(useCase);
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
    KeyManagerHealthController keyManagerHealthController(ConnectionFactory connectionFactory) {
        return new KeyManagerHealthController(connectionFactory);
    }
}