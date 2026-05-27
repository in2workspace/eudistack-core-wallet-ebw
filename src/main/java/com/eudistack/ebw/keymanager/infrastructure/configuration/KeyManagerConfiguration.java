package com.eudistack.ebw.keymanager.infrastructure.configuration;

import com.eudistack.ebw.keymanager.application.AlgorithmNegotiator;
import com.eudistack.ebw.keymanager.application.HolderKeyFactory;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyReadPort;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyWritePort;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.HolderKeyR2dbcAdapter;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.spring.SpringHolderKeyRepository;
import com.eudistack.ebw.keymanager.infrastructure.health.KeyManagerHealthController;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.r2dbc.spi.ConnectionFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.r2dbc.core.DatabaseClient;

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
    KeyManagerHealthController keyManagerHealthController(ConnectionFactory connectionFactory) {
        return new KeyManagerHealthController(connectionFactory);
    }
}