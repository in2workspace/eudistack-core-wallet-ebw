package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import com.eudistack.ebw.keymanager.application.EnrollHolderUseCase;
import com.eudistack.ebw.keymanager.domain.exception.InvalidCommitException;
import com.eudistack.ebw.keymanager.domain.exception.TenantWalletProfileUnsupportedException;
import com.eudistack.ebw.keymanager.domain.exception.PrfUnsupportedException;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto.BlockOnboardingRequest;
import com.eudistack.ebw.keymanager.domain.model.EnrollHolderCommitRequest;
import com.eudistack.ebw.keymanager.domain.model.EnrollHolderCommitResponse;
import com.eudistack.ebw.keymanager.domain.model.EnrollHolderInitRequest;
import com.eudistack.ebw.keymanager.domain.model.EnrollHolderInitResponse;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import com.eudistack.ebw.wallet.profile.domain.model.TenantWalletProfile;
import com.eudistack.ebw.wallet.profile.domain.model.WalletMode;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * REST controller for the hybrid (Passkey PRF) onboarding flow.
 *
 * <p>Endpoints:
 * <ul>
 *   <li>{@code POST /api/v1/keys/hybrid/onboarding/init} — returns the PRF salt and KDF
 *       parameters so the Wallet PWA can derive the wrap key client-side (200 OK).</li>
 *   <li>{@code POST /api/v1/keys/hybrid/onboarding/commit} — receives and persists the
 *       AES-256-GCM-wrapped holder private key (201 Created).</li>
 * </ul>
 *
 * <p>Both endpoints reject with {@code 403} if the tenant's wallet profile is not
 * {@code (SERVER, HYBRID)}, preventing non-hybrid tenants from reaching these routes.</p>
 *
 * <p>The {@code holder_id} is extracted from the DPoP-bound JWT session and MUST NOT be
 * accepted from the request body (AC-06; architecture.md §8.1).</p>
 *
 * <p>Spec: EUDISTACK-534 AC-01..AC-07, ES-01..ES-05; architecture.md §6.1.</p>
 */
@RestController
@RequestMapping("/api/v1/keys/hybrid/onboarding")
@Validated
public class HybridOnboardingController {

    private final EnrollHolderUseCase enrollHolderUseCase;
    private final WalletProfileQueryPort walletProfileQueryPort;
    private final ObjectMapper objectMapper;

    public HybridOnboardingController(EnrollHolderUseCase enrollHolderUseCase,
                                       WalletProfileQueryPort walletProfileQueryPort,
                                       ObjectMapper objectMapper) {
        this.enrollHolderUseCase = enrollHolderUseCase;
        this.walletProfileQueryPort = walletProfileQueryPort;
        this.objectMapper = objectMapper;
    }

    /**
     * Initialises the hybrid onboarding flow for a credential.
     *
     * <p>Returns the PRF salt (32 bytes, base64url) and static KDF parameters. The Wallet PWA
     * uses these to execute the WebAuthn PRF ceremony and derive the wrap key client-side.
     * Salt generation is delegated to US-05 (EUDISTACK-537) via {@link EnrollHolderUseCase#init}.</p>
     *
     * @param request the init request carrying {@code credential_id} and {@code format}
     * @param auth    the DPoP-bound authenticated holder principal
     * @return 200 OK with PRF salt and KDF parameters
     */
    @PostMapping("/init")
    public Mono<ResponseEntity<EnrollHolderInitResponse>> init(
            @Valid @RequestBody EnrollHolderInitRequest request,
            JwtAuthenticationToken auth) {

        String holderId = auth.getUserId().toString();

        return walletProfileQueryPort.queryByCurrentTenant()
                .flatMap(profile -> requireHybridWalletProfile(profile)
                        .then(Mono.deferContextual(ctx -> {
                            String tenantId = ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, "");
                            return enrollHolderUseCase.init(tenantId, holderId, request);
                        })))
                .map(ResponseEntity::ok);
    }

    /**
     * Commits the wrapped holder key after client-side key generation and wrapping.
     *
     * <p>Persists exactly one wrapped key handle per {@code (holderId, credentialId)} pair.
     * Identical re-submits are acknowledged (AC-07). Different blobs for the same pair are
     * rejected with 409 (ES-03).</p>
     *
     * @param request the commit request carrying wrapped blob, IV, tag, KDF metadata, and cnf JWK
     * @param auth    the DPoP-bound authenticated holder principal
     * @return 201 Created (first-time commit) or 200 OK (idempotent replay — AC-07)
     */
    @PostMapping("/commit")
    public Mono<ResponseEntity<EnrollHolderCommitResponse>> commit(
            @Valid @RequestBody EnrollHolderCommitRequest request,
            JwtAuthenticationToken auth) {

        // Validate cnf_jwk: must be valid JSON without private key parameter "d" (AC-03)
        try {
            Map<String, Object> jwk = objectMapper.readValue(request.cnfJwk(), new TypeReference<>() {});
            if (jwk.containsKey("d")) {
                return Mono.error(new InvalidCommitException(
                        "cnf_jwk must not contain private key parameter 'd' (AC-03)"));
            }
        } catch (JsonProcessingException e) {
            return Mono.error(new InvalidCommitException("cnf_jwk is not valid JSON"));
        }

        String holderId = auth.getUserId().toString();

        return walletProfileQueryPort.queryByCurrentTenant()
                .flatMap(profile -> requireHybridWalletProfile(profile)
                        .then(enrollHolderUseCase.commit(holderId, request)))
                .map(response -> ResponseEntity.status(
                        response.replay() ? HttpStatus.OK : HttpStatus.CREATED).body(response));
    }

    @PostMapping("/block")
    public Mono<Void> block(@Valid @RequestBody BlockOnboardingRequest request, JwtAuthenticationToken auth) {
        return walletProfileQueryPort.queryByCurrentTenant()
                .flatMap(profile -> requireHybridWalletProfile(profile)
                        .then(Mono.error(new PrfUnsupportedException())));
    }

    private Mono<Void> requireHybridWalletProfile(TenantWalletProfile profile) {
        if (profile.walletMode() != WalletMode.SERVER || profile.keyManager() != KeyManager.HYBRID) {
            return Mono.deferContextual(ctx -> Mono.error(new TenantWalletProfileUnsupportedException(
                    ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, "unknown"))));
        }
        return Mono.empty();
    }
}