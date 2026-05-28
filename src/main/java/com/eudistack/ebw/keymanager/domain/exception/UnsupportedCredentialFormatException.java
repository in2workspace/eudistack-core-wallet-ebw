package com.eudistack.ebw.keymanager.domain.exception;

import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;

/**
 * Thrown when a credential format is presented that is not supported by the Key Manager.
 *
 * <p>The message includes the format identifier to aid diagnostics, but contains no key material.</p>
 *
 * <p>Spec: EUDISTACK-119 AC-05, OID4VCI 1.0 §4 (credential format identifier).</p>
 */
public class UnsupportedCredentialFormatException extends RuntimeException {

    public UnsupportedCredentialFormatException(CredentialFormat format) {
        super("Unsupported credential format: " + format);
    }

    public UnsupportedCredentialFormatException(String format) {
        super("Unsupported credential format: " + format);
    }
}
