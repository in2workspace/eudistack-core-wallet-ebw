package com.eudistack.ebw.keymanager.domain.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Response confirming a successful hybrid onboarding commit (201 new / 200 replay).
 *
 * <p>Returns only the enrolled {@code credential_id}. No cryptographic material
 * (wrapped blob, PRF salt, IV, or tag) is echoed back in the response (NFR-04, NFR-06).</p>
 *
 * <p>{@code replay} is an internal flag used by the controller to choose between 201
 * (first-time commit) and 200 (idempotent replay — AC-07). It is excluded from JSON.</p>
 *
 * <p>Spec: EUDISTACK-534 AC-04, AC-06, AC-07; architecture.md §6.1 step 8.</p>
 */
public record EnrollHolderCommitResponse(
        @JsonProperty("credential_id") String credentialId,
        @JsonIgnore boolean replay
) {}