package com.eudistack.ebw.keymanager.domain.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Response confirming a successful hybrid onboarding commit (HTTP 201).
 *
 * <p>Returns only the enrolled {@code credential_id}. No cryptographic material
 * (wrapped blob, PRF salt, IV, or tag) is echoed back in the response (NFR-04, NFR-06).</p>
 *
 * <p>Spec: EUDISTACK-534 AC-04, AC-06; architecture.md §6.1 step 8.</p>
 */
public record EnrollHolderCommitResponse(
        @JsonProperty("credential_id") String credentialId
) {}