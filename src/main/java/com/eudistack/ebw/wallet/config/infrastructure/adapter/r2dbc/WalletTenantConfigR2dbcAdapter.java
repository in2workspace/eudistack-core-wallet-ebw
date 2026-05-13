package com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.wallet.config.domain.model.TenantWalletConfigDescriptor;
import com.eudistack.ebw.wallet.config.domain.port.TenantConfigurationPort;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.entity.WalletTenantConfigEntity;
import com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.mapper.WalletTenantConfigMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.data.relational.core.query.Criteria;
import org.springframework.data.relational.core.query.Query;
import reactor.core.publisher.Mono;

/**
 * R2DBC implementation of {@link TenantConfigurationPort} — read-only discovery path.
 *
 * <p>Uses the {@code @Qualifier("publicSchema")} {@link R2dbcEntityTemplate} which connects to
 * {@code public.tenant_wallet_config} via a dedicated connection pool whose {@code search_path}
 * is permanently fixed to {@code public}. This pool NEVER passes through
 * {@code TenantAwareConnectionFactoryDecorator} (AD-1, AD-S2).
 *
 * <p>The lookup uses an explicit column projection via {@link WalletTenantConfigEntity} — never
 * {@code SELECT *}. The write/UPSERT path moved to EUDISTACK-55 along with the rest of the
 * discovery-plane write side; in this Story the table is seeded via SQL.
 */
public class WalletTenantConfigR2dbcAdapter implements TenantConfigurationPort {

    private static final Logger log = LoggerFactory.getLogger(WalletTenantConfigR2dbcAdapter.class);

    private final R2dbcEntityTemplate readTemplate;

    /**
     * @param readTemplate read-only R2DBC template backed by the {@code publicSchema} pool
     */
    public WalletTenantConfigR2dbcAdapter(R2dbcEntityTemplate readTemplate) {
        this.readTemplate = readTemplate;
    }

    @Override
    public Mono<TenantWalletConfigDescriptor> findByHost(String host) {
        String normalizedHost = host.toLowerCase();
        log.debug("Looking up tenant_wallet_config for host={}", normalizedHost);
        return readTemplate
                .selectOne(
                        Query.query(Criteria.where("host").is(normalizedHost)),
                        WalletTenantConfigEntity.class)
                .map(WalletTenantConfigMapper::toDescriptor)
                .doOnSuccess(d -> {
                    if (d != null) {
                        log.debug("Found tenant_wallet_config: schemaName={}, walletMode={}",
                                d.getSchemaName(), d.getWalletMode());
                    } else {
                        log.debug("No tenant_wallet_config found for host={}", normalizedHost);
                    }
                });
    }
}
