package com.eudistack.ebw.keymanager.domain.model;

/**
 * Declares the purpose for which a signing operation is being performed.
 *
 * <p>{@link #PRESENTATION} is the default purpose for all consumer-driven signing requests
 * (EUDISTACK-6/7/8). {@link #AUDIT_PROBE} is reserved exclusively for Security Lead canary
 * checks — it produces the same cryptographic output but is labelled separately in the
 * audit log so that canary events can be filtered out of operational metrics.</p>
 *
 * <p>The metric histogram {@code keymanager_sign_duration_seconds} includes a {@code purpose}
 * label to separate canary latency measurements from real presentation latency.</p>
 *
 * <p>Spec: EUDISTACK-407 EC-05, FR-60.</p>
 */
public enum SignaturePurpose {

    /**
     * A signing request originated from a credential presentation flow (OID4VP / SD-JWT VC kb-jwt).
     * This is the default purpose for consumers EUDISTACK-6, EUDISTACK-7, and EUDISTACK-8.
     */
    PRESENTATION,

    /**
     * A canary signing request issued by the Security Lead to verify operational health.
     * The JWS output is valid but must not be used in a real presentation.
     */
    AUDIT_PROBE
}
