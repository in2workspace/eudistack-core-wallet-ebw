package com.eudistack.ebw.keymanager.domain.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

/**
 * Request to commit the wrapped holder key after client-side generation.
 *
 * <p>The Wallet PWA submits the AES-256-GCM-encrypted holder private key together with
 * the public JWK ({@code cnf_jwk}) to be embedded in the credential's {@code cnf.jwk}
 * claim. Only the ciphertext ({@code wrapped_blob}, {@code iv}, {@code tag}) and the
 * public key travel to the server — the plaintext private key and wrap key MUST remain
 * in the client's volatile memory only and be zeroed after use (AC-02, AC-03).</p>
 *
 * <p>Byte-length invariants ({@code wrapped_blob} ≥ 48 B; {@code iv} = 12 B;
 * {@code tag} = 16 B) are enforced in
 * {@link com.eudistack.ebw.keymanager.application.EnrollHolderUseCase} because they
 * cannot be expressed via Bean Validation on base64url strings.</p>
 *
 * <p>The {@code holder_id} is extracted from the DPoP session by the controller (AC-06).
 * It MUST NOT appear in this record.</p>
 *
 * <p>Spec: EUDISTACK-534 AC-02, AC-03, AC-04, AC-06; FR-05, FR-06; architecture.md §6.1 step 7.</p>
 */
public record EnrollHolderCommitRequest(
        @NotBlank @Size(max = 512) @JsonProperty("credential_id") String credentialId,
        @NotBlank @Size(max = 8192) @JsonProperty("wrapped_blob") String wrappedBlob,
        @NotBlank @Size(min = 16, max = 18) @JsonProperty("iv") String iv,
        @NotBlank @Size(min = 22, max = 24) @JsonProperty("tag") String tag,
        @NotBlank @Size(max = 32) @JsonProperty("kdf_algo") String kdfAlgo,
        @NotNull @Positive @JsonProperty("kdf_version") Integer kdfVersion,
        @NotBlank @Size(max = 4096) @JsonProperty("cnf_jwk") String cnfJwk
) {}