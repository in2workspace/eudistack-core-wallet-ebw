package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.domain.model.CustodyMode;
import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.model.WalletCredential;
import com.eudistack.ebw.domain.model.exception.HolderKeyMismatchException;
import com.eudistack.ebw.domain.spi.HolderKeyMaterialPort;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyId;
import com.eudistack.ebw.keymanager.domain.model.JwkPublic;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent;
import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent.KeyAuditEventType;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyReadPort;
import com.eudistack.ebw.keymanager.domain.port.HolderKeyWritePort;
import com.eudistack.ebw.keymanager.domain.port.KeyAuditPort;
import reactor.core.publisher.Mono;
import reactor.util.context.ContextView;

import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * Checks that an attestation is bound to the key of its holder key and deletes that key's material
 * with the attestation (EUD-11 FR-05, FR-10, FR-16).
 *
 * <p>The keys are compared by their JWK thumbprint (RFC 7638). No private key and no salt reach a
 * log or an audit event.</p>
 */
public class HolderKeyMaterialService implements HolderKeyMaterialPort {

    private static final int COORDINATE_BYTES = 32;

    private final HolderKeyReadPort holderKeyReadPort;
    private final HolderKeyWritePort holderKeyWritePort;
    private final PrfSaltPort prfSaltPort;
    private final KeyAuditPort auditPort;

    public HolderKeyMaterialService(HolderKeyReadPort holderKeyReadPort, HolderKeyWritePort holderKeyWritePort,
                                    PrfSaltPort prfSaltPort, KeyAuditPort auditPort) {
        this.holderKeyReadPort = holderKeyReadPort;
        this.holderKeyWritePort = holderKeyWritePort;
        this.prfSaltPort = prfSaltPort;
        this.auditPort = auditPort;
    }

    @Override
    public Mono<Void> verify(Binding binding) {
        Mono<Map<String, Object>> holderKey = binding.mode() == CustodyMode.SERVER
                ? serverHolderPublicJwk(binding)
                : passkeyHolderPublicJwk(binding);
        return holderKey.flatMap(holderJwk -> sameKey(binding.cnfJwk(), holderJwk)
                ? Mono.<Void>empty()
                : Mono.error(new HolderKeyMismatchException("The attestation is not bound to the holder key")));
    }

    @Override
    public Mono<Void> keepPublicKey(Binding binding) {
        if (binding.mode() != CustodyMode.PASSKEY) {
            return Mono.empty();
        }
        return Mono.defer(() -> prfSaltPort.setPublicJwk(binding.userId().toString(), binding.holderKeyId(),
                        binding.passkeyId().toString(), publicKeyOf(binding.holderPublicJwk())))
                .filter(Boolean::booleanValue)
                .switchIfEmpty(Mono.error(new HolderKeyMismatchException("The holder key has no salt to keep its public key")))
                .then();
    }

    @Override
    public Mono<Void> delete(WalletCredential credential) {
        if (credential.getCustodyMode() == null || credential.getHolderKeyId() == null) {
            return Mono.empty();
        }
        String holderId = credential.getUserId().toString();
        String credentialId = credential.getHolderKeyId();
        return switch (credential.getCustodyMode()) {
            case SERVER -> deleteServerKey(holderId, credentialId);
            case PASSKEY -> prfSaltPort.delete(holderId, credentialId)
                    .filter(Boolean::booleanValue)
                    .flatMap(deleted -> emitSaltDeleted(holderId, credentialId));
        };
    }

    private Mono<Map<String, Object>> serverHolderPublicJwk(Binding binding) {
        return Mono.deferContextual(ctx -> parseKeyId(binding.holderKeyId())
                .flatMap(keyId -> holderKeyReadPort.findById(tenantOf(ctx), binding.userId().toString(), keyId))
                .map(key -> key.publicJwk().claims())
                .switchIfEmpty(Mono.error(new HolderKeyMismatchException("The holder key does not exist"))));
    }

    private Mono<Map<String, Object>> passkeyHolderPublicJwk(Binding binding) {
        if (binding.holderKeyId() == null || binding.holderPublicJwk() == null) {
            return Mono.error(new HolderKeyMismatchException("The holder public key is required"));
        }
        return prfSaltPort.findBy(binding.userId().toString(), binding.holderKeyId())
                .filter(salt -> salt.isOwnedBy(binding.passkeyId().toString()))
                .switchIfEmpty(Mono.error(new HolderKeyMismatchException("The holder key has no salt of this passkey")))
                .map(salt -> publicKeyOf(binding.holderPublicJwk()));
    }

    private Mono<Void> deleteServerKey(String holderId, String keyIdValue) {
        return Mono.deferContextual(ctx -> parseKeyId(keyIdValue)
                .flatMap(keyId -> holderKeyReadPort.findById(tenantOf(ctx), holderId, keyId)
                        .flatMap(key -> holderKeyWritePort.deleteById(tenantOf(ctx), holderId, keyId)
                                .filter(Boolean::booleanValue)
                                .flatMap(deleted -> emit(() -> KeyAuditEvent.forKeyDeleted(tenantOf(ctx), holderId,
                                        key.credentialId(), keyIdValue, Instant.now(),
                                        UUID.randomUUID().toString()))))));
    }

    private Mono<Void> emitSaltDeleted(String holderId, String credentialId) {
        return Mono.deferContextual(ctx -> emit(() -> KeyAuditEvent.forSalt(KeyAuditEventType.SALT_DELETED,
                tenantOf(ctx), holderId, credentialId, null, Instant.now(), UUID.randomUUID().toString())));
    }

    /** Audit is best effort: a broken audit channel, or an event that cannot be built, must not fail the deletion. */
    private Mono<Void> emit(Supplier<KeyAuditEvent> event) {
        return Mono.defer(() -> auditPort.emit(event.get())).onErrorResume(e -> Mono.empty());
    }

    private static Mono<HolderKeyId> parseKeyId(String value) {
        try {
            return Mono.just(HolderKeyId.of(UUID.fromString(value)));
        } catch (IllegalArgumentException | NullPointerException _) {
            return Mono.error(new HolderKeyMismatchException("The holder key id is not valid"));
        }
    }

    private static String tenantOf(ContextView ctx) {
        return ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, "");
    }

    /**
     * The public key the Wallet App derived, reduced to {@code kty}, {@code crv}, {@code x} and {@code y}.
     * It must be an EC P-256 public key: one that carries the private member {@code d}, or has coordinates
     * that are not 32 bytes, is rejected, and any other member is dropped, so nothing else is stored.
     */
    private static Map<String, Object> publicKeyOf(Map<String, Object> jwk) {
        if (jwk == null || jwk.containsKey("d")
                || !"EC".equals(jwk.get("kty")) || !"P-256".equals(jwk.get("crv"))
                || !isCoordinate(jwk.get("x")) || !isCoordinate(jwk.get("y"))) {
            throw new HolderKeyMismatchException("The holder public key is not an EC P-256 public key");
        }
        return Map.of("kty", "EC", "crv", "P-256", "x", jwk.get("x"), "y", jwk.get("y"));
    }

    private static boolean isCoordinate(Object value) {
        if (!(value instanceof String text)) {
            return false;
        }
        try {
            return Base64.getUrlDecoder().decode(text).length == COORDINATE_BYTES;
        } catch (IllegalArgumentException _) {
            return false;
        }
    }

    private static boolean sameKey(Map<String, Object> cnfJwk, Map<String, Object> holderJwk) {
        if (cnfJwk == null) {
            return false;
        }
        try {
            return new JwkPublic(cnfJwk).jkt().equals(new JwkPublic(holderJwk).jkt());
        } catch (RuntimeException _) {
            return false;
        }
    }
}
