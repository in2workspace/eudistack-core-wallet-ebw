package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.wallet.profile.domain.exception.TenantUnknownException;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import com.eudistack.ebw.wallet.profile.domain.model.WalletMode;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Whether the current tenant has passkey custody of the holder keys (wallet profile
 * {@code server} + key manager {@code passkey-prf}). A tenant without wallet profile does not.
 */
@Service
public class PasskeyCustodyPolicy {

    private final WalletProfileQueryPort walletProfileQueryPort;

    public PasskeyCustodyPolicy(WalletProfileQueryPort walletProfileQueryPort) {
        this.walletProfileQueryPort = walletProfileQueryPort;
    }

    public Mono<Boolean> isPasskeyCustody() {
        return walletProfileQueryPort.queryByCurrentTenant()
                .map(profile -> profile.walletMode() == WalletMode.SERVER
                        && profile.keyManager() == KeyManager.PASSKEY_PRF)
                .onErrorResume(TenantUnknownException.class, e -> Mono.just(false));
    }
}
