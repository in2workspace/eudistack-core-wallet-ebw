package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.WalletCredential;
import com.eudistack.ebw.wallet.profile.domain.exception.TenantUnknownException;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import com.eudistack.ebw.wallet.profile.domain.model.WalletMode;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.UUID;

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

    /**
     * The attestation if the session may see it: always without passkey custody; with it, only
     * unbound attestations and those of the session's passkey (EUD-11 FR-14). Empty otherwise.
     */
    public Mono<WalletCredential> visibleToSession(WalletCredential credential, UUID sessionPasskeyId) {
        if (credential.isVisibleToPasskey(sessionPasskeyId)) {
            return Mono.just(credential);
        }
        return isPasskeyCustody().flatMap(custody -> Boolean.TRUE.equals(custody) ? Mono.empty() : Mono.just(credential));
    }

    public Mono<Boolean> isPasskeyCustody() {
        return walletProfileQueryPort.queryByCurrentTenant()
                .map(profile -> profile.walletMode() == WalletMode.SERVER
                        && profile.keyManager() == KeyManager.PASSKEY_PRF)
                .onErrorResume(TenantUnknownException.class, e -> Mono.just(false));
    }
}
