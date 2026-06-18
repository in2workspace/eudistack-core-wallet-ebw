package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
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

import java.util.Map;

/**
 * REST controller for the hybrid (Passkey PRF) two-step signing handshake and audit events.
 *
 * <p>Endpoints:
 * <ul>
 *   <li>{@code POST /api/v1/keys/hybrid/sign/prepare} — initiates the handshake: the server
 *       returns the PRF salt + wrapped-blob envelope so the PWA can derive the unwrap key
 *       client-side via Passkey PRF (US-01 skeleton; cryptographic logic in US-04).</li>
 *   <li>{@code POST /api/v1/keys/hybrid/sign/submit} — finalises the handshake: the PWA
 *       submits the client-side signed assertion; the server verifies and produces the
 *       key-binding JWT (US-01 skeleton; cryptographic logic in US-04).</li>
 *   <li>{@code POST /api/v1/keys/hybrid/constraint-accepted} — records the holder's acceptance
 *       of the multi-device limitation in the audit log (US-06, EUDISTACK-538).</li>
 * </ul>
 *
 * <p>All endpoints reject with {@code 403} if the tenant's wallet profile is not
 * {@code (SERVER, HYBRID)}, preventing DB tenants from reaching hybrid routes.</p>
 *
 * <p>Spec: EUDISTACK-533 FR-03, AC-03, AC-04, AC-05, ES-01, ES-03;
 */
@RestController
@RequestMapping("/api/v1/keys/hybrid")
@Validated
public class HybridKeyManagerController {

    private final KeyManagerPort hybridAdapter;
    private final WalletProfileQueryPort walletProfileQueryPort;
    private final AuditService auditService;

    public HybridKeyManagerController(KeyManagerPort hybridAdapter,
                                       WalletProfileQueryPort walletProfileQueryPort,
                                       AuditService auditService) {
        this.hybridAdapter = hybridAdapter;
        this.walletProfileQueryPort = walletProfileQueryPort;
        this.auditService = auditService;
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
    @PostMapping("/sign/prepare")
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
    @PostMapping("/sign/submit")
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

    /**
     * Records the holder's acceptance of the multi-device constraint in the audit log.
     *
     * <p>The PWA calls this endpoint once, immediately after the user taps "accept" on the
     * hybrid onboarding screen and before any holder key is generated (US-06, AC-02).
     * The actor identity is taken from the authenticated JWT — no request body is needed.</p>
     *
     * @param auth the authenticated holder principal
     * @return 204 No Content on success
     */
    @PostMapping("/constraint-accepted")
    public Mono<ResponseEntity<Void>> acceptConstraint(JwtAuthenticationToken auth) {

        return walletProfileQueryPort.queryByCurrentTenant()
                .flatMap(profile -> {
                    if (profile.walletMode() != WalletMode.SERVER
                            || profile.keyManager() != KeyManager.HYBRID) {
                        return Mono.deferContextual(ctx ->
                                Mono.error(new TenantWalletProfileUnsupportedException(
                                        ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, "unknown"))));
                    }
                    return auditService.record(
                            "hybrid_consent",
                            auth.getUserId(),
                            "hybrid_constraint_accepted",
                            auth.getUserId(),
                            Map.of("key_manager", "hybrid")
                    );
                })
                .thenReturn(ResponseEntity.<Void>noContent().build());
    }
}
