package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;

/**
 * Immutable snapshot of a pending (or resolved) hybrid signing session.
 *
 * <p>Stored by {@link PreparedSignStore} keyed on {@code correlationId} (UUID v7, TTL ≤ 5 min).
 * Transitions from {@code pending} (resolvedKbJwt == null) to {@code resolved}
 * (resolvedKbJwt != null) once {@code submitSignedAssertion} succeeds.</p>
 *
 * <p>None of these fields contain {@code prf_salt}, wrap key, or holder private key material —
 * only the public JWK and the signing input are needed server-side (NFR-S-536-03).</p>
 *
 * <p>Spec: EUDISTACK-536 EC-03; architecture.md §8.1 (idempotency model).</p>
 *
 * @param signingInput  the ASCII {@code base64url(header) + "." + base64url(payload)} string
 *                      that the client signed client-side with {@code SubtleCrypto.sign(ES256)}.
 *                      Used by the EBW to verify the submitted signature and to assemble the
 *                      final {@code kb_jwt} compact serialisation.
 * @param cnfJwk        the public JWK JSON string ({@code cnf.jwk}, no private-key parameter
 *                      {@code "d"}) extracted from {@link com.eudistack.ebw.keymanager.domain.model.WrappedKeyHandle}.
 *                      Used by {@code SubmitSignedUseCase} for cryptographic verification.
 * @param holderId      the holder UUID string extracted from the DPoP session; carried here so
 *                      {@code submitSignedAssertion} can enforce holder isolation without an
 *                      extra DB look-up (ES-04).
 * @param tenantId      the tenant domain extracted from the Reactor context at prepare time;
 *                      carried here so {@code submitSignedAssertion} can emit a complete audit
 *                      event without an extra DB look-up (F2, NIS2 non-repudiation).
 * @param credentialId  the credential identifier; carried for traceability and log correlation.
 * @param format        the credential format validated at prepare time; carried for audit (F2).
 * @param resolvedKbJwt the compact {@code kb_jwt} returned on a successful first submit;
 *                      {@code null} while the session is pending. Idempotent replays of
 *                      {@code submitSignedAssertion} return this cached value (EC-03).
 */
public record PreparedSign(
        String signingInput,
        String cnfJwk,
        String holderId,
        String tenantId,
        String credentialId,
        CredentialFormat format,
        String resolvedKbJwt
) {

    /** True while no successful submit has been recorded for this correlation session. */
    public boolean isPending() {
        return resolvedKbJwt == null;
    }

    /** Returns a copy of this record with {@code resolvedKbJwt} set. */
    public PreparedSign withResolved(String kbJwt) {
        return new PreparedSign(signingInput, cnfJwk, holderId, tenantId, credentialId, format, kbJwt);
    }
}

