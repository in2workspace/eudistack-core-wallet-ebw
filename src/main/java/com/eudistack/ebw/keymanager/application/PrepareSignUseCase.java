package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.keymanager.domain.exception.PrfSaltNotFoundException;
import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.PrepareSignRequest;
import com.eudistack.ebw.keymanager.domain.model.PrepareSignResponse;
import com.eudistack.ebw.keymanager.domain.model.WrappedKeyHandle;
import com.eudistack.ebw.keymanager.domain.port.WrappedKeyHandleRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.JWK;
import reactor.core.publisher.Mono;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Application use case for the hybrid (Passkey PRF) signing handshake — prepare step.
 *
 * <p>Resolves the {@code prf_salt} (US-05) and the {@code wrapped key handle} (US-02) for the
 * requesting holder's credential, assembles the {@code signing_input} (JWS header.payload that
 * the PWA will sign client-side), stores the pending session in {@link PreparedSignStore} for
 * idempotent retrieval by {@link SubmitSignedUseCase}, and returns the complete
 * {@link PrepareSignResponse} envelope.</p>
 *
 * <p>Holder isolation: the {@code holderId} is always extracted from the Reactor context
 * (set by {@code HybridKeyManagerController} from the DPoP-bound JWT) — never from the
 * request body (ES-04).</p>
 *
 * <p>Error paths (all errors propagate as reactive signals — NFR-S-536-02):
 * <ul>
 *   <li>prf_salt absent for this holder → {@link PrfSaltNotFoundException} (404 {@code wrap_handle_not_found})</li>
 *   <li>prf_salt exists for another holder → {@link com.eudistack.ebw.keymanager.domain.exception.HolderIsolationViolationException} (403)</li>
 *   <li>wrapped key handle absent → {@link PrfSaltNotFoundException} (404 {@code wrap_handle_not_found})</li>
 *   <li>DB timeout/failure → upstream R2DBC error propagated reactively (ES-06)</li>
 * </ul>
 *
 * <p>Spec: EUDISTACK-536 AC-01, AC-03, AC-08, EC-03, ES-02, ES-04, ES-06,
 * NFR-S-536-01, NFR-S-536-02; architecture.md §6.2.</p>
 */
public class PrepareSignUseCase {

    private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();
    private static final JOSEObjectType KB_JWT_TYPE = new JOSEObjectType("kb+jwt");
    private static final JOSEObjectType VP_JWT_TYPE = new JOSEObjectType("vp+jwt");
    private static final JWSHeader KB_JWT_HEADER = new JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(KB_JWT_TYPE)
            .build();

    private final PrfSaltUseCase prfSaltUseCase;
    private final WrappedKeyHandleRepository wrappedKeyHandleRepository;
    private final PreparedSignStore preparedSignStore;
    private final ObjectMapper objectMapper;

    public PrepareSignUseCase(PrfSaltUseCase prfSaltUseCase,
                               WrappedKeyHandleRepository wrappedKeyHandleRepository,
                               PreparedSignStore preparedSignStore,
                               ObjectMapper objectMapper) {
        this.prfSaltUseCase = prfSaltUseCase;
        this.wrappedKeyHandleRepository = wrappedKeyHandleRepository;
        this.preparedSignStore = preparedSignStore;
        this.objectMapper = objectMapper;
    }

    /**
     * Executes the prepare step of the hybrid signing handshake.
     *
     * <p>Reads {@code holderId} and {@code tenantId} from the Reactor context (written by the
     * controller from the DPoP JWT). Resolves {@code prf_salt} and the wrapped key handle in
     * parallel, then assembles and stores the signing session.</p>
     *
     * @param correlationId server-generated correlation id minted by the adapter (B2: generated
     *                      outside the use case so error-path spans can be tagged before
     *                      the use case is entered).
     */
    public Mono<PrepareSignResponse> execute(PrepareSignRequest request, String correlationId) {
        return Mono.deferContextual(ctx -> {
            String holderId = ctx.get(ReactorContextKeys.HOLDER_ID);
            String tenantId = ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, "");

            Mono<byte[]> prfSaltMono = prfSaltUseCase.getForHolder(tenantId, holderId, request.credentialId());
            Mono<WrappedKeyHandle> handleMono = wrappedKeyHandleRepository
                    .findBy(holderId, request.credentialId())
                    .flatMap(opt -> opt
                            .<Mono<WrappedKeyHandle>>map(Mono::just)
                            .orElseGet(() -> Mono.error(
                                    new PrfSaltNotFoundException(request.credentialId()))));

            return Mono.zip(prfSaltMono, handleMono)
                    .flatMap(tuple -> buildAndStore(
                            request, holderId, tenantId, correlationId, tuple.getT1(), tuple.getT2()));
        });
    }

    private Mono<PrepareSignResponse> buildAndStore(PrepareSignRequest request,
                                                     String holderId,
                                                     String tenantId,
                                                     String correlationId,
                                                     byte[] prfSalt,
                                                     WrappedKeyHandle handle) {
        return Mono.fromCallable(() -> {
            CredentialFormat format = formatFrom(request.format());
            String signingInput = buildSigningInput(request.payload(), format, handle.cnfJwk());
            String kdfParams = buildKdfParams(handle);

            PreparedSign prepared = new PreparedSign(
                    signingInput, handle.cnfJwk(), holderId, tenantId,
                    request.credentialId(), format, null);
            PrepareSignResponse response = new PrepareSignResponse(
                    BASE64URL.encodeToString(prfSalt),
                    BASE64URL.encodeToString(handle.wrappedBlob()),
                    BASE64URL.encodeToString(handle.iv()),
                    BASE64URL.encodeToString(handle.tag()),
                    kdfParams,
                    signingInput,
                    correlationId);

            return new PrepareBundle(correlationId, prepared, response);
        }).flatMap(bundle -> preparedSignStore
                .putPending(bundle.correlationId(), bundle.prepared())
                .thenReturn(bundle.response()));
    }

    private static CredentialFormat formatFrom(String requestFormat) {
        return switch (requestFormat) {
            case "vc+sd-jwt" -> CredentialFormat.SD_JWT_VC;
            case "jwt_vc_json" -> CredentialFormat.VC_JWT;
            default -> throw new IllegalStateException("Unexpected format: " + requestFormat);
        };
    }

    private String buildSigningInput(Map<String, Object> payload, CredentialFormat format, String cnfJwk) {
        try {
            JWSHeader header = buildHeader(format, cnfJwk);
            String payloadJson = objectMapper.writeValueAsString(payload);
            return header.toBase64URL() + "." + new Payload(payloadJson).toBase64URL();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build signing_input", e);
        }
    }

    private JWSHeader buildHeader(CredentialFormat format, String cnfJwk) {
        return switch (format) {
            case SD_JWT_VC -> KB_JWT_HEADER;
            case VC_JWT -> buildVpEnvelopeHeader(cnfJwk);
        };
    }

    private JWSHeader buildVpEnvelopeHeader(String cnfJwk) {
        try {
            JWK jwk = JWK.parse(cnfJwk).toPublicJWK();
            return new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(VP_JWT_TYPE)
                    .contentType("vp")
                    .jwk(jwk)
                    .keyID(jwk.computeThumbprint().toString())
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Stored cnf.jwk is malformed", e);
        }
    }

    private String buildKdfParams(WrappedKeyHandle handle) {
        try {
            Map<String, Object> kdfMap = new LinkedHashMap<>();
            kdfMap.put("alg", handle.kdfAlgo());
            kdfMap.put("version", handle.kdfVersion());
            kdfMap.put("info", "hybrid-wrap-v1");
            kdfMap.put("L", 256);
            return objectMapper.writeValueAsString(kdfMap);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build kdf_params", e);
        }
    }

    private record PrepareBundle(String correlationId, PreparedSign prepared,
                                  PrepareSignResponse response) {}
}
