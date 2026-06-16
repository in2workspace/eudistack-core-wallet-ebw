package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.keymanager.domain.exception.TenantWalletProfileUnsupportedException;
import com.eudistack.ebw.keymanager.domain.model.PrepareSignRequest;
import com.eudistack.ebw.keymanager.domain.model.PrepareSignResponse;
import com.eudistack.ebw.keymanager.domain.model.SubmitSignedAssertionRequest;
import com.eudistack.ebw.keymanager.domain.model.SubmitSignedAssertionResponse;
import com.eudistack.ebw.keymanager.domain.port.KeyManagerPort;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import com.eudistack.ebw.wallet.profile.domain.model.WalletMode;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * REST controller for the hybrid (Passkey PRF) two-step signing handshake.
 *
 * <p>Endpoints:
 * <ul>
 *   <li>{@code POST /api/v1/keys/hybrid/sign/prepare} — initiates the handshake: the server
 *       returns the PRF salt + wrapped-blob envelope so the PWA can derive the unwrap key
 *       client-side via Passkey PRF (US-01 skeleton; cryptographic logic in US-04).</li>
 *   <li>{@code POST /api/v1/keys/hybrid/sign/submit} — finalises the handshake: the PWA
 *       submits the client-side signed assertion; the server verifies and produces the
 *       key-binding JWT (US-01 skeleton; cryptographic logic in US-04).</li>
 * </ul>
 *
 * <p>Both endpoints reject with {@code 403} if the tenant's wallet profile is not
 * {@code (SERVER, HYBRID)}, preventing DB tenants from reaching hybrid routes.</p>
 *
 * <p>Spec: EUDISTACK-533 FR-03, AC-03, AC-04, AC-05, ES-01, ES-03;
 * architecture.md §6.1 (runtime flows).</p>
 */
@RestController
@RequestMapping("/api/v1/keys/hybrid/sign")
@Validated
public class HybridKeyManagerController {

    private final KeyManagerPort hybridAdapter;
    private final WalletProfileQueryPort walletProfileQueryPort;

    public HybridKeyManagerController(KeyManagerPort hybridAdapter,
                                       WalletProfileQueryPort walletProfileQueryPort) {
        this.hybridAdapter = hybridAdapter;
        this.walletProfileQueryPort = walletProfileQueryPort;
    }

    /**
     * Initiates the hybrid signing handshake.
     *
     * <p>Returns the PRF challenge metadata (salt, wrapped blob, IV, tag, KDF params, signing input,
     * correlation ID). The PWA uses these to derive the unwrap key via Passkey PRF and sign
     * the payload client-side, then submits back via {@link #submit}.</p>
     *
     * @param request the prepare request carrying {@code credential_id}, {@code vp_challenge},
     *                and {@code format}
     * @return 200 with the PRF challenge envelope
     */
    @PostMapping("/prepare")
    public Mono<ResponseEntity<PrepareSignResponse>> prepare(
            @Valid @RequestBody PrepareSignRequest request) {

        return walletProfileQueryPort.queryByCurrentTenant()
                .flatMap(profile -> {
                    if (profile.walletMode() != WalletMode.SERVER
                            || profile.keyManager() != KeyManager.HYBRID) {
                        return Mono.deferContextual(ctx ->
                                Mono.error(new TenantWalletProfileUnsupportedException(
                                        ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, "unknown"))));
                    }
                    return hybridAdapter.prepareSign(request);
                })
                .map(ResponseEntity::ok);
    }

    /**
     * Finalises the hybrid signing handshake and produces the key-binding JWT.
     *
     * <p>The PWA echoes the {@code correlation_id} from the prepare response along with
     * the PRF-derived signature. The EBW verifies the assertion and returns the
     * {@code kb+jwt} compact serialisation.</p>
     *
     * @param request the submit request carrying {@code credential_id}, {@code signature},
     *                and {@code correlation_id}
     * @return 200 with the key-binding JWT
     */
    @PostMapping("/submit")
    public Mono<ResponseEntity<SubmitSignedAssertionResponse>> submit(
            @Valid @RequestBody SubmitSignedAssertionRequest request) {

        return walletProfileQueryPort.queryByCurrentTenant()
                .flatMap(profile -> {
                    if (profile.walletMode() != WalletMode.SERVER
                            || profile.keyManager() != KeyManager.HYBRID) {
                        return Mono.deferContextual(ctx ->
                                Mono.error(new TenantWalletProfileUnsupportedException(
                                        ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, "unknown"))));
                    }
                    return hybridAdapter.submitSignedAssertion(request);
                })
                .map(ResponseEntity::ok);
    }
}
