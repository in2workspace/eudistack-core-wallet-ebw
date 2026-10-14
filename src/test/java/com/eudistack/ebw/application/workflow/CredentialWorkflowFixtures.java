package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.CredentialFormat;
import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.model.WalletCredential;
import com.eudistack.ebw.infrastructure.controller.dto.VerifiableCredentialResponse;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Shared builders for the credential workflow unit tests.
 */
final class CredentialWorkflowFixtures {

    private CredentialWorkflowFixtures() {}

    static WalletCredential credential(UUID id, UUID userId, CredentialStatus status) {
        var now = Instant.now();
        return new WalletCredential(id, userId, "raw-credential", CredentialFormat.DC_SD_JWT, "cfg-1", "kid-1",
                "LEARCredentialEmployee", "urn:vct:lear", "https://issuer", "did:sub", now, null,
                status, Map.of(), "hk-1", now, now);
    }

    static VerifiableCredentialResponse response(String id) {
        return new VerifiableCredentialResponse(List.of(), id, List.of("VerifiableCredential"), "VALID",
                null, null, null, null, null, Map.of(), null, null, "dc+sd-jwt", null, null);
    }
}
