package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import com.eudistack.ebw.keymanager.domain.exception.TenantWalletProfileUnsupportedException;
import com.eudistack.ebw.keymanager.domain.exception.UnsupportedCredentialFormatException;
import com.eudistack.ebw.keymanager.domain.model.ConsumerOrigin;
import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.GenerateHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyId;
import com.eudistack.ebw.keymanager.domain.model.SignHolderKeyCommand;
import com.eudistack.ebw.keymanager.domain.port.KeyManagerPort;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto.GenerateHolderKeyRequest;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto.GenerateHolderKeyResponse;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto.SignHolderKeyRequest;
import com.eudistack.ebw.keymanager.infrastructure.adapter.http.dto.SignHolderKeyResponse;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import com.eudistack.ebw.wallet.profile.domain.model.WalletMode;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Base64;
import java.util.UUID;

/**
 * REST controller exposing the key manager endpoints.
 *
 * <p>Endpoints:
 * <ul>
 *   <li>{@code POST /api/v1/keys/generate} — generates a holder key and OID4VCI proof JWT
 *       (US-02 EUDISTACK-119)</li>
 *   <li>{@code POST /api/v1/keys/{keyId}/sign} — signs a payload on behalf of the holder
 *       (US-03 EUDISTACK-407)</li>
 * </ul>
 *
 * <p>Both endpoints validate that the current tenant's wallet profile is {@code (SERVER, DB)}
 * before delegating. The signing endpoint additionally resolves {@code ConsumerOrigin} from
 * the optional header {@code X-Consumer-Origin} (default {@link ConsumerOrigin#SYSTEM}).</p>
 *
 * <p>Spec: EUDISTACK-119 AC-01..AC-06, EUDISTACK-407 AC-01..AC-09, ES-01..ES-05.</p>
 */
@RestController
@RequestMapping("/api/v1/keys")
@Validated
public class KeyManagerController {

    private static final String HEADER_CONSUMER_ORIGIN = "X-Consumer-Origin";

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

    /**
     * Signs a payload on behalf of the holder using the key identified by {@code keyId}.
     *
     * <p>The {@code signing_input} in the request body is treated as opaque bytes (base64url-encoded).
     * The EBW does not validate or parse the semantic structure — that responsibility belongs to
     * the consumer (EC-03).</p>
     *
     * <p>Rejection paths (key not found, revoked, cross-tenant) produce an opaque 401 with a
     * constant-time response per ADR-025.</p>
     *
     * @param keyId          surrogate key identifier from the key generation response
     * @param request        the signing request body
     * @param auth           the authenticated holder principal
     * @param consumerOrigin optional origin header; defaults to {@link ConsumerOrigin#SYSTEM}
     * @return 200 with JWS compact serialization, algorithm, and JWK thumbprint
     */
    @PostMapping("/{keyId}/sign")
    public Mono<ResponseEntity<SignHolderKeyResponse>> sign(
            @PathVariable String keyId,
            @Valid @RequestBody SignHolderKeyRequest request,
            JwtAuthenticationToken auth,
            @RequestHeader(name = HEADER_CONSUMER_ORIGIN, required = false) String consumerOriginHeader) {

        String holderId = auth.getUserId().toString();
        ConsumerOrigin origin = parseConsumerOrigin(consumerOriginHeader);
        HolderKeyId holderKeyId = parseKeyId(keyId);

        return Mono.deferContextual(ctx -> {
            String tenantId = ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, "");
            byte[] signingInputBytes = Base64.getUrlDecoder().decode(request.signingInput());
            SignHolderKeyCommand command = new SignHolderKeyCommand(
                    holderKeyId, tenantId, holderId,
                    request.signingType(), request.purpose(), origin,
                    signingInputBytes);
            return keyManagerPort.signWithHolderKey(command);
        }).map(result -> ResponseEntity.ok(SignHolderKeyResponse.from(result)));
    }

    // --- private helpers ---

    private static CredentialFormat parseFormat(String format) {
        try {
            return CredentialFormat.fromDbValue(format);
        } catch (IllegalArgumentException e) {
            throw new UnsupportedCredentialFormatException(format);
        }
    }

    private static ConsumerOrigin parseConsumerOrigin(String headerValue) {
        if (headerValue == null || headerValue.isBlank()) {
            return ConsumerOrigin.SYSTEM;
        }
        try {
            return ConsumerOrigin.valueOf(headerValue.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return ConsumerOrigin.SYSTEM;
        }
    }

    private static HolderKeyId parseKeyId(String keyId) {
        try {
            return HolderKeyId.of(UUID.fromString(keyId));
        } catch (IllegalArgumentException e) {
            throw new com.eudistack.ebw.keymanager.domain.exception.KeyAccessDeniedException("INVALID_KEY_ID_FORMAT");
        }
    }
}
