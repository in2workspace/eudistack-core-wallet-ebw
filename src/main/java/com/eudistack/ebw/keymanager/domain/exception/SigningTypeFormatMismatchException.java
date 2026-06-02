package com.eudistack.ebw.keymanager.domain.exception;

import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.SigningType;

/**
 * Thrown when the requested {@link SigningType} is not compatible with the stored
 * {@link CredentialFormat} of the holder key (EC-02).
 *
 * <p>Example: consumer requests {@code KB_JWT} signing but the key was generated for
 * a {@code VC_JWT} credential. This is a consumer programming error — the caller should
 * consult the key metadata before choosing the signing type.</p>
 *
 * <p>This exception is mapped to HTTP 400 (see {@code KeyManagerExceptionHandler}).
 * Unlike {@link KeyAccessDeniedException} (opaque 401), this one is developer-visible
 * because the mismatch reveals no secret: the consumer already knows the credential format
 * they are working with.</p>
 *
 * <p>Spec: EUDISTACK-407 AC-04, EC-02.</p>
 */
public class SigningTypeFormatMismatchException extends RuntimeException {

    public SigningTypeFormatMismatchException(SigningType signingType, CredentialFormat format) {
        super("SigningType " + signingType + " is not compatible with credential format " + format);
    }
}
