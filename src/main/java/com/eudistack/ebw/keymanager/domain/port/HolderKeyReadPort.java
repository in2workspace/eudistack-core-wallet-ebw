package com.eudistack.ebw.keymanager.domain.port;

import com.eudistack.ebw.keymanager.domain.model.HolderKey;
import reactor.core.publisher.Mono;

public interface HolderKeyReadPort {

    Mono<HolderKey> findByKeyId(String keyId);

    Mono<HolderKey> findActiveByHolderAndCredential(String holderId, String credentialId);
}