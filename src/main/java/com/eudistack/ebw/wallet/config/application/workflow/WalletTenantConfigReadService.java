package com.eudistack.ebw.wallet.config.application.workflow;

import com.eudistack.ebw.wallet.config.domain.model.TenantWalletConfigDescriptor;
import com.eudistack.ebw.wallet.config.domain.port.TenantConfigurationPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Application use case for the public discovery read path.
 *
 * <p>Retrieves the {@link TenantWalletConfigDescriptor} for a given tenant host.
 * This endpoint is public and requires no authentication — callers are EUDIW browser clients
 * bootstrapping themselves against the discovery plane (AC-1).
 *
 * <p>When no configuration exists for the given host, an empty {@link Mono} is returned.
 * The controller layer is responsible for converting the empty signal into an HTTP 404 response.
 *
 * <p>No mutation occurs here — this service is read-only.
 */
@Service
public class WalletTenantConfigReadService {

    private static final Logger log = LoggerFactory.getLogger(WalletTenantConfigReadService.class);

    private final TenantConfigurationPort tenantConfigurationPort;

    public WalletTenantConfigReadService(TenantConfigurationPort tenantConfigurationPort) {
        this.tenantConfigurationPort = tenantConfigurationPort;
    }

    /**
     * Retrieves the wallet configuration descriptor for the given tenant host.
     *
     * <p>The host is expected to be already normalised to lowercase by the caller
     * (per the normalisation policy in AC-1d). No further transformation is applied here.
     *
     * @param host the tenant hostname (e.g. {@code acme.eudiw.example.com})
     * @return a {@link Mono} emitting the descriptor, or an empty {@link Mono} if not found
     */
    public Mono<TenantWalletConfigDescriptor> retrieveDescriptor(String host) {
        log.debug("Retrieving wallet tenant config for host={}", host);
        return tenantConfigurationPort.findByHost(host)
                .doOnSuccess(descriptor -> {
                    if (descriptor != null) {
                        log.info("Wallet tenant config found: host={}, walletMode={}, version={}",
                                host, descriptor.getWalletMode(), descriptor.getVersion());
                    }
                })
                .doOnError(e -> log.error("Failed to retrieve wallet tenant config: host={}, error={}",
                        host, e.getMessage()));
    }
}
