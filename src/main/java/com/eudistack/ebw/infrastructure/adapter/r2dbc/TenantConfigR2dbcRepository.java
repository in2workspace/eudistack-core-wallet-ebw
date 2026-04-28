package com.eudistack.ebw.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.TenantConfig;
import com.eudistack.ebw.domain.repository.TenantConfigRepository;
import com.eudistack.ebw.infrastructure.adapter.r2dbc.spring.SpringTenantConfigRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public class TenantConfigR2dbcRepository implements TenantConfigRepository {

    private final SpringTenantConfigRepository springRepository;

    public TenantConfigR2dbcRepository(SpringTenantConfigRepository springRepository) {
        this.springRepository = springRepository;
    }

    @Override
    public Mono<TenantConfig> findByConfigKey(String configKey) {
        return springRepository.findByConfigKey(configKey)
                .map(e -> new TenantConfig(
                        e.getId(),
                        e.getConfigKey(),
                        e.getConfigValue(),
                        e.getDescription(),
                        e.getCreatedAt(),
                        e.getUpdatedAt()
                ));
    }
}
