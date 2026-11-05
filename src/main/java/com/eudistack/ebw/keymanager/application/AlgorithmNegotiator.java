package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.exception.UnsupportedJwsAlgorithmException;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;

import java.util.List;

/**
 * Checks that the issuer accepts the only algorithm holder keys use.
 *
 * <p>Holder keys are always ES256 (EUD-11 FR-02). Matching is case-sensitive and exact per
 * OID4VCI 1.0 §7.2.1.</p>
 *
 * <p>This class is a pure function — stateless, no I/O, no side-effects. It is
 * instantiated as a Spring bean in {@code KeyManagerConfiguration}.</p>
 *
 * <p>Spec: OID4VCI 1.0 §7.2.1 (proof JWT header {@code alg}), EUD-11 design 1.1.0 §2.1.</p>
 */
public class AlgorithmNegotiator {

    private static final List<String> SUPPORTED = List.of(KeyAlgorithm.ES256.getJwsAlgorithmName());

    /**
     * @param supportedByIssuer the list of JWS algorithm names advertised by the issuer;
     *                          must not be null or empty
     * @return {@link KeyAlgorithm#ES256}
     * @throws UnsupportedJwsAlgorithmException if {@code ES256} is not in the list or the
     *                                          input is null/empty
     */
    public KeyAlgorithm negotiate(List<String> supportedByIssuer) {
        if (supportedByIssuer == null || !supportedByIssuer.contains(KeyAlgorithm.ES256.getJwsAlgorithmName())) {
            throw new UnsupportedJwsAlgorithmException(
                    supportedByIssuer == null ? List.of() : supportedByIssuer, SUPPORTED);
        }
        return KeyAlgorithm.ES256;
    }
}