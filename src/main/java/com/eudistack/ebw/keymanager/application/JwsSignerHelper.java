package com.eudistack.ebw.keymanager.application;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.PrivateKey;
import java.security.Signature;
import java.util.Set;

/**
 * Shared package-private helpers for producing JWS signatures in the application layer.
 *
 * <p>This class exists to eliminate the duplication of {@code buildEdDsaSignerBC} between
 * {@link KbJwtSigner} and {@link VpEnvelopeSigner} (W3 — code-review finding).</p>
 *
 * <p>Contains only static, pure helper methods — no state, no Spring dependencies.</p>
 */
final class JwsSignerHelper {

    private JwsSignerHelper() {
        // utility class — no instances
    }

    /**
     * Builds a BouncyCastle-backed Ed25519 {@link JWSSigner}.
     *
     * <p>This helper avoids the Google Tink dependency, which is an optional transitive
     * dependency of nimbus-jose-jwt that may not be present in this module.</p>
     *
     * @param key the Ed25519 private key
     * @return a {@link JWSSigner} backed by BouncyCastle
     */
    static JWSSigner buildEdDsaSignerBC(PrivateKey key) {
        return new JWSSigner() {
            private final JCAContext jcaContext = new JCAContext();

            @Override
            public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
                try {
                    Signature sig = Signature.getInstance(
                            "Ed25519", BouncyCastleProvider.PROVIDER_NAME);
                    sig.initSign(key);
                    sig.update(signingInput);
                    return Base64URL.encode(sig.sign());
                } catch (Exception e) {
                    throw new JOSEException("Ed25519 sign failed (BouncyCastle)", e);
                }
            }

            @Override
            public Set<JWSAlgorithm> supportedJWSAlgorithms() {
                return Set.of(JWSAlgorithm.EdDSA);
            }

            @Override
            public JCAContext getJCAContext() {
                return jcaContext;
            }
        };
    }
}
