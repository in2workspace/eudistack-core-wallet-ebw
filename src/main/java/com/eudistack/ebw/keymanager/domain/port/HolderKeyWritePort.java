package com.eudistack.ebw.keymanager.domain.port;

import com.eudistack.ebw.keymanager.domain.model.HolderKey;
import reactor.core.publisher.Mono;

public interface HolderKeyWritePort {

    Mono<HolderKey> save(HolderKey holderKey);
}