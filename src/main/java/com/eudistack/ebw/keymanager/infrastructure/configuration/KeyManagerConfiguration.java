package com.eudistack.ebw.keymanager.infrastructure.configuration;

import com.eudistack.ebw.infrastructure.adapter.properties.EncryptionProperties;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyCipherPort;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyReadPort;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyWritePort;
import com.eudistack.ebw.keymanager.infrastructure.adapter.crypto.AesGcmHolderKeyCipherAdapter;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.HolderKeyR2dbcAdapter;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.spring.SpringHolderKeyRepository;
import com.eudistack.ebw.keymanager.infrastructure.health.KeyManagerHealthController;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KeyManagerConfiguration {

    @Bean
    HolderKeyCipherPort holderKeyCipherPort(EncryptionProperties encryptionProperties) {
        return new AesGcmHolderKeyCipherAdapter(encryptionProperties);
    }

    @Bean
    HolderKeyR2dbcAdapter holderKeyR2dbcAdapter(SpringHolderKeyRepository repository) {
        return new HolderKeyR2dbcAdapter(repository);
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
    KeyManagerHealthController keyManagerHealthController(HolderKeyCipherPort cipherPort) {
        return new KeyManagerHealthController(cipherPort);
    }
}