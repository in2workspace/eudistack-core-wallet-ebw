package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.domain.model.exception.InvalidSessionException;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import com.eudistack.ebw.keymanager.application.PrfSaltUseCase;
import com.eudistack.ebw.keymanager.domain.exception.TenantWalletProfileUnsupportedException;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto.CreatePrfSaltRequest;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto.PrfSaltResponse;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import com.eudistack.ebw.wallet.profile.domain.model.WalletMode;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * Salt and public key of the attestations obtained with passkey custody (EUD-11 design §2.2).
 *
 * <p>The passkey is always the one of the session ({@code pkid} of the access token): the Wallet
 * App cannot declare another. Answers 409 when the tenant has no passkey custody.</p>
 */
@RestController
@RequestMapping("/api/v1/keys/passkey-prf/salts")
@Validated
public class PasskeyPrfSaltController {

    private final PrfSaltUseCase prfSaltUseCase;
    private final WalletProfileQueryPort walletProfileQueryPort;

    public PasskeyPrfSaltController(PrfSaltUseCase prfSaltUseCase, WalletProfileQueryPort walletProfileQueryPort) {
        this.prfSaltUseCase = prfSaltUseCase;
        this.walletProfileQueryPort = walletProfileQueryPort;
    }

    /** Creates the salt of a new attestation, or returns the one this passkey already created. */
    @PostMapping
    public Mono<ResponseEntity<PrfSaltResponse>> create(@Valid @RequestBody CreatePrfSaltRequest request,
                                                        JwtAuthenticationToken auth) {
        UUID passkeyId = requirePasskey(auth);
        return requirePasskeyCustody()
                .flatMap(tenantId -> prfSaltUseCase.createForPasskey(tenantId, auth.getUserId().toString(),
                        passkeyId.toString(), request.credentialId()))
                .map(salt -> ResponseEntity.status(HttpStatus.CREATED).body(PrfSaltResponse.withoutPublicKey(salt)));
    }

    /** Returns the salt and the public key of an attestation of the passkey of the session. */
    @GetMapping("/{credentialId}")
    public Mono<PrfSaltResponse> get(@PathVariable @NotBlank @Size(max = 512) String credentialId,
                                     JwtAuthenticationToken auth) {
        UUID passkeyId = requirePasskey(auth);
        return requirePasskeyCustody()
                .flatMap(tenantId -> prfSaltUseCase.getForPasskey(tenantId, auth.getUserId().toString(),
                        passkeyId.toString(), credentialId))
                .map(PrfSaltResponse::withPublicKey);
    }

    private static UUID requirePasskey(JwtAuthenticationToken auth) {
        if (auth.getPasskeyId() == null) {
            throw new InvalidSessionException();
        }
        return auth.getPasskeyId();
    }

    private Mono<String> requirePasskeyCustody() {
        return walletProfileQueryPort.queryByCurrentTenant()
                .flatMap(profile -> profile.walletMode() == WalletMode.SERVER
                        && profile.keyManager() == KeyManager.PASSKEY_PRF
                        ? Mono.just(profile.tenant())
                        : Mono.error(new TenantWalletProfileUnsupportedException(profile.tenant())));
    }
}
