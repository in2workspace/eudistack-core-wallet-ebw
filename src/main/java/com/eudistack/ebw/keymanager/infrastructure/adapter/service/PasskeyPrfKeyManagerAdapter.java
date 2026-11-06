package com.eudistack.ebw.keymanager.infrastructure.adapter.service;

import com.eudistack.ebw.keymanager.domain.exception.TenantWalletProfileUnsupportedException;
import com.eudistack.ebw.keymanager.domain.model.GenerateHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyResult;
import com.eudistack.ebw.keymanager.domain.model.SignHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.SignHolderKeyResult;
import com.eudistack.ebw.keymanager.domain.port.KeyManagerPort;
import reactor.core.publisher.Mono;

/**
 * {@link KeyManagerPort} of a tenant with passkey custody. The Wallet Unit Service holds no key there:
 * the Wallet App derives it on the device and signs itself, so the server custody operations
 * (generate and sign) do not belong to this mode and answer {@code unsupported custody mode}.
 */
public class PasskeyPrfKeyManagerAdapter implements KeyManagerPort {

    @Override
    public Mono<HolderKeyResult> generateHolderKey(GenerateHolderKeyCommand command) {
        return Mono.error(new TenantWalletProfileUnsupportedException(command.tenantId()));
    }

    @Override
    public Mono<SignHolderKeyResult> signWithHolderKey(SignHolderKeyCommand cmd) {
        return Mono.error(new TenantWalletProfileUnsupportedException(cmd.tenantId()));
    }
}
