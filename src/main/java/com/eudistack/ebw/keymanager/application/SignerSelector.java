package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.exception.UnsupportedSigningTypeException;
import com.eudistack.ebw.keymanager.domain.model.SigningType;

import java.util.Map;
import java.util.Objects;

/**
 * Pure function that selects the appropriate {@link JwsSigner} for a given {@link SigningType}.
 *
 * <p>The signer registry is a {@code Map<SigningType, JwsSigner>} injected at construction
 * time via {@code KeyManagerConfiguration}. This allows future extension (e.g. mdoc DeviceAuth)
 * by registering a new entry without modifying this class or {@code SignHolderKeyUseCase}.</p>
 *
 * <p>If no signer is registered for the requested type, an
 * {@link UnsupportedSigningTypeException} is thrown (maps to HTTP 400).</p>
 *
 * <p>Spec: EUDISTACK-407 AC-03.</p>
 */
public class SignerSelector {

    private final Map<SigningType, JwsSigner> signers;

    /**
     * @param signers registry of available signers; must not be null or empty
     */
    public SignerSelector(Map<SigningType, JwsSigner> signers) {
        Objects.requireNonNull(signers, "signers must not be null");
        if (signers.isEmpty()) {
            throw new IllegalArgumentException("signers registry must not be empty");
        }
        this.signers = Map.copyOf(signers);
    }

    /**
     * Returns the {@link JwsSigner} registered for the given signing type.
     *
     * @param type the requested signing type; must not be null
     * @return the registered signer
     * @throws UnsupportedSigningTypeException if no signer is registered for {@code type}
     */
    public JwsSigner select(SigningType type) {
        Objects.requireNonNull(type, "signingType must not be null");
        JwsSigner signer = signers.get(type);
        if (signer == null) {
            throw new UnsupportedSigningTypeException(type);
        }
        return signer;
    }
}
