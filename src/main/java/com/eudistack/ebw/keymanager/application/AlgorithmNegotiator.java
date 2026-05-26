package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.exception.UnsupportedJwsAlgorithmException;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;

import java.util.List;

/**
 * Selects the best JWS algorithm supported by both parties.
 *
 * <p>The preference order is hardcoded per ADR-024: EdDSA &gt; ES384 &gt; ES256.
 * The negotiation iterates over the preference list in order and returns the first
 * algorithm whose {@link KeyAlgorithm#getJwsAlgorithmName()} is present in the
 * issuer-advertised list. Matching is case-sensitive and exact per OID4VCI 1.0 §7.2.1.</p>
 *
 * <p>This class is a pure function — stateless, no I/O, no side-effects. It is
 * instantiated as a Spring bean in {@code KeyManagerConfiguration}.</p>
 *
 * <p>Spec: ADR-024, OID4VCI 1.0 §7.2.1 (proof JWT header {@code alg}), EUDISTACK-119 AC-05.</p>
 */
public class AlgorithmNegotiator {

    /**
     * Preference list per ADR-024: EdDSA &gt; ES384 &gt; ES256.
     */
    private static final List<KeyAlgorithm> PREFERENCE_ORDER =
            List.of(KeyAlgorithm.EdDSA, KeyAlgorithm.ES384, KeyAlgorithm.ES256);

    /**
     * Selects the highest-preference algorithm that appears in {@code supportedByIssuer}.
     *
     * @param supportedByIssuer the list of JWS algorithm names advertised by the issuer;
     *                          must not be null or empty
     * @return the selected {@link KeyAlgorithm}
     * @throws UnsupportedJwsAlgorithmException if the intersection is empty or the input
     *                                          is null/empty
     */
    public KeyAlgorithm negotiate(List<String> supportedByIssuer) {
        if (supportedByIssuer == null || supportedByIssuer.isEmpty()) {
            throw new UnsupportedJwsAlgorithmException(
                    List.of(),
                    List.of("EdDSA", "ES384", "ES256")
            );
        }

        for (KeyAlgorithm candidate : PREFERENCE_ORDER) {
            if (supportedByIssuer.contains(candidate.getJwsAlgorithmName())) {
                return candidate;
            }
        }

        throw new UnsupportedJwsAlgorithmException(
                supportedByIssuer,
                List.of("EdDSA", "ES384", "ES256")
        );
    }
}