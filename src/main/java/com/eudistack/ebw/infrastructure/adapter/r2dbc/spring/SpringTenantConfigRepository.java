package com.eudistack.ebw.infrastructure.adapter.r2dbc.spring;

import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.TenantConfigEntity;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface SpringTenantConfigRepository extends ReactiveCrudRepository<TenantConfigEntity, UUID> {

    Mono<TenantConfigEntity> findByConfigKey(String configKey);
}
