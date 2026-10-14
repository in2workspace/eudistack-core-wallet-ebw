package com.eudistack.ebw.domain.repository;

import reactor.core.publisher.Mono;

public interface TenantRegistryRepository {

    /** Display name of the tenant in {@code public.tenant_registry}; empty when the tenant is not registered. */
    Mono<String> findDisplayName(String tenantId);
}
