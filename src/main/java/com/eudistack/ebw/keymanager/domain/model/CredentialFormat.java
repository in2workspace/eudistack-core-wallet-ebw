package com.eudistack.ebw.keymanager.domain.model;

/**
 * Credential formats supported by the Key Manager bounded context.
 *
 * <p>This enum is intentionally separate from {@code com.eudistack.ebw.domain.model.CredentialFormat}
 * to avoid coupling the keymanager bounded context to the wallet storage domain, which uses
 * different format identifiers (e.g. {@code dc+sd-jwt} vs {@code SD_JWT_VC}).</p>
 *
 * <p>Spec: OID4VCI 1.0 §4 (credential format identifier), ADR-021.</p>
 */
public enum CredentialFormat {

    SD_JWT_VC,
    VC_JWT;
}