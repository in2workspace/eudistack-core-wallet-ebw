package com.eudistack.ebw.keymanager.domain.exception;

import com.eudistack.ebw.keymanager.domain.model.SigningType;

/**
 * Thrown when the requested {@link SigningType} is not registered in {@code SignerSelector}
 * (AC-03).
 *
 * <p>This covers the case where the consumer requests a signing type that has no registered
 * {@code JwsSigner} implementation. Currently, only {@code KB_JWT} and {@code VP_ENVELOPE}
 * are supported. Future extension points (e.g. mdoc DeviceAuth) would require registering
 * a new signer before the corresponding type can be used.</p>
 *
 * <p>This exception is mapped to HTTP 400 (see {@code KeyManagerExceptionHandler}).</p>
 *
 * <p>Spec: EUDISTACK-407 AC-03.</p>
 */
public class UnsupportedSigningTypeException extends RuntimeException {

    public UnsupportedSigningTypeException(SigningType signingType) {
        super("No signer registered for signing type: " + signingType);
    }
}
