package com.eudistack.ebw.keymanager.domain.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Response to the hybrid onboarding init step.
 *
 * <p>All byte fields are base64url-encoded without padding. The Wallet PWA uses these
 * values to:
 * <ol>
 *   <li>Execute {@code navigator.credentials.create({prf:{eval:{first: prfSalt}}})}.</li>
 *   <li>Derive the wrap key: {@code HKDF-SHA-256(ikm=prfOutput, salt=credentialId_bytes, info="hybrid-wrap-v1")}.</li>
 *   <li>Generate the holder ECDSA P-256 key pair and wrap the private key with AES-256-GCM.</li>
 * </ol>
 *
 * <p>The {@code prf_salt} MUST NOT appear in logs, errors, or audit events (NFR-06).</p>
 *
 * <p>Spec: EUDISTACK-534 AC-01, AC-02; architecture.md §6.1 step 5.</p>
 */
public record EnrollHolderInitResponse(
        @JsonProperty("prf_salt") String prfSalt,
        @JsonProperty("kdf_params") String kdfParams,
        @JsonProperty("signing_pubkey_envelope_format") String signingPubkeyEnvelopeFormat
) {}