package com.eudistack.ebw.domain.repository;

import com.eudistack.ebw.domain.model.TenantConfig;
import reactor.core.publisher.Mono;

public interface TenantConfigRepository {

    Mono<TenantConfig> findByConfigKey(String configKey);
}
