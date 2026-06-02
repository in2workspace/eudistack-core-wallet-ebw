package com.eudistack.ebw.keymanager.domain.model;

/**
 * Identifies which EBW subsystem or external consumer initiated the signing request.
 *
 * <p>This value is derived from the optional HTTP header {@code X-Consumer-Origin}
 * sent by the caller. If the header is absent, {@link #SYSTEM} is used as the default
 * (internal call without explicit origin declaration).</p>
 *
 * <p>The value is recorded in the audit event ({@code consumer_origin} field) to support
 * forensic analysis — e.g. determining whether an anomalous signing pattern originated
 * from the credential storage flow or from an OID4VP responder.</p>
 *
 * <p>Spec: EUDISTACK-407, FR-60, ADR-069.</p>
 */
public enum ConsumerOrigin {

    /**
     * Request originated from the credential storage subsystem (wallet credential persistence).
     */
    STORAGE,

    /**
     * Request originated from the OID4VCI credential issuance responder.
     */
    OID4VCI_RESPONDER,

    /**
     * Request originated from the OID4VP verifiable presentation responder.
     */
    OID4VP_RESPONDER,

    /**
     * Request originated from an internal system call with no explicit consumer declaration,
     * or from a consumer that did not include the {@code X-Consumer-Origin} header.
     * This is the default.
     */
    SYSTEM
}
