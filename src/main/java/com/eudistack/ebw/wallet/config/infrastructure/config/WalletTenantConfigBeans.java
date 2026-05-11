package com.eudistack.ebw.wallet.config.infrastructure.config;

import com.eudistack.ebw.wallet.config.domain.service.TenantWalletConfigInvariants;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring bean definitions for the {@code wallet.config} bounded context.
 *
 * <p>Exposes framework-free domain services as Spring-managed beans so that the
 * application layer can receive them via constructor injection. Domain classes must
 * remain free of {@code @Component} or any other Spring annotation.
 *
 * <p>Infrastructure adapters (connection pools, CloudFront client) will be registered
 * here in subsequent tasks (Task 4 — discovery read path, Task 5 — admin write path).
 */
@Configuration
public class WalletTenantConfigBeans {

    @Bean
    public TenantWalletConfigInvariants tenantWalletConfigInvariants() {
        return new TenantWalletConfigInvariants();
    }
}
