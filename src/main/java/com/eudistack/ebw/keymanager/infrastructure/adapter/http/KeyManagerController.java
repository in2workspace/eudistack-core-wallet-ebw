package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import com.eudistack.ebw.keymanager.domain.exception.UnsupportedCredentialFormatException;
import com.eudistack.ebw.keymanager.domain.exception.TenantWalletProfileUnsupportedException;
import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.GenerateHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.port.KeyManagerPort;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto.GenerateHolderKeyRequest;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto.GenerateHolderKeyResponse;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import com.eudistack.ebw.wallet.profile.domain.model.WalletMode;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * REST controller exposing the key manager endpoint.
 *
 * <p>Path: {@code POST /api/v1/keys/generate}
 *
 * <p>Validates that the current tenant's wallet profile is {@code (SERVER, DB)} before
 * delegating to the domain port. Non-conforming tenants receive a 403 Forbidden with
 * no body (ES-02 anti-probing — AD-119-2).</p>
 *
 * <p>The tenant identifier is resolved from the Reactor Context key
 * {@link ReactorContextKeys#TENANT_DOMAIN} set by the upstream {@code TenantDomainWebFilter}.
 * The holder identifier is resolved from the JWT authentication principal.</p>
 *
 * <p>Spec: EUDISTACK-119 AC-01, AC-02, AC-03, AC-06, ES-01, ES-02, ADR-021, ADR-024.</p>
 */
@RestController
@RequestMapping("/api/v1/keys")
@Validated
public class KeyManagerController {

    private final KeyManagerPort keyManagerPort;
    private final WalletProfileQueryPort walletProfileQueryPort;

    public KeyManagerController(KeyManagerPort keyManagerPort,
                                 WalletProfileQueryPort walletProfileQueryPort) {
        this.keyManagerPort = keyManagerPort;
        this.walletProfileQueryPort = walletProfileQueryPort;
    }

    /**
     * Generates a holder key and OID4VCI {@code jwt} proof for credential issuance.
     *
     * <p>Returns 201 Created on success. When an existing key is reused due to concurrent
     * issuance (EC-01 / ES-03), the response includes {@code warning: "existing_key_algorithm_used"}.</p>
     *
     * @param request OID4VCI proof request
     * @param auth    the authenticated holder principal
     * @return 201 with the key identifier, public JWK, and signed proof
     */
    @PostMapping("/generate")
    public Mono<ResponseEntity<GenerateHolderKeyResponse>> generate(
            @Valid @RequestBody GenerateHolderKeyRequest request,
            JwtAuthenticationToken auth) {

        CredentialFormat format = parseFormat(request.format());
        String holderId = auth.getUserId().toString();

        return walletProfileQueryPort.queryByCurrentTenant()
                .flatMap(profile -> {
                    if (profile.walletMode() != WalletMode.SERVER
                            || profile.keyManager() != KeyManager.DB) {
                        return Mono.deferContextual(ctx ->
                                Mono.error(new TenantWalletProfileUnsupportedException(
                                        ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, "unknown"))));
                    }
                    return Mono.deferContextual(ctx -> {
                        String tenantId = ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, "");
                        GenerateHolderKeyCommand command = new GenerateHolderKeyCommand(
                                tenantId, holderId, request.credentialId(), format,
                                request.supportedAlgs(), request.issuerIdentifier(),
                                request.cNonce());
                        return keyManagerPort.generateHolderKey(command);
                    });
                })
                .map(result -> ResponseEntity
                        .status(HttpStatus.CREATED)
                        .body(GenerateHolderKeyResponse.from(result)));
    }

    private static CredentialFormat parseFormat(String format) {
        try {
            return CredentialFormat.fromDbValue(format);
        } catch (IllegalArgumentException e) {
            throw new UnsupportedCredentialFormatException(format);
        }
    }
}