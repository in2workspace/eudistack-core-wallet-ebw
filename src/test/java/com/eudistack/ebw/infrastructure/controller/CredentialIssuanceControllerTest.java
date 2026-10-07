package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.StoreCredentialWorkflow;
import com.eudistack.ebw.domain.model.CredentialFormat;
import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.model.WalletCredential;
import com.eudistack.ebw.infrastructure.controller.dto.FinalizeIssuanceRequest;
import com.eudistack.ebw.infrastructure.controller.dto.FinalizeIssuanceRequest.CredentialItem;
import com.eudistack.ebw.infrastructure.controller.dto.FinalizeIssuanceRequest.CredentialResponse;
import com.eudistack.ebw.infrastructure.controller.dto.FinalizeIssuanceRequest.CredentialResponseWithStatus;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link CredentialIssuanceController} — the OID4VCI credential response is unwrapped and stored,
 * with empty defaults for the optional holder kid and issuer metadata.
 */
@ExtendWith(MockitoExtension.class)
class CredentialIssuanceControllerTest {

    private static final UUID USER_ID = UUID.randomUUID();

    @Mock private StoreCredentialWorkflow storeCredentialWorkflow;

    private CredentialIssuanceController controller;
    private JwtAuthenticationToken auth;

    @BeforeEach
    void setUp() {
        controller = new CredentialIssuanceController(storeCredentialWorkflow);
        auth = new JwtAuthenticationToken(USER_ID, "holder@example.com", List.of());
    }

    @Test
    void finalizeIssuance_fullRequest_storesTheFirstCredentialWithHolderKey() {
        // Arrange
        var metadata = Map.<String, Object>of("credential_issuer", "https://issuer");
        var request = request(List.of(new CredentialItem("raw-1"), new CredentialItem("raw-2")),
                metadata, "hk-1", "did:key:holder#0");
        var stored = credential();
        when(storeCredentialWorkflow.storeCredential(USER_ID, "raw-1", "dc+sd-jwt", "cfg-1", "did:key:holder#0",
                metadata, "hk-1")).thenReturn(Mono.just(stored));

        // Act
        var result = controller.finalizeIssuance(request, auth);

        // Assert
        StepVerifier.create(result)
                .assertNext(detail -> assertThat(detail.id()).isEqualTo(stored.getId()))
                .verifyComplete();
    }

    @Test
    void finalizeIssuance_withoutHolderKidOrMetadata_usesEmptyDefaults() {
        // Arrange
        var request = request(List.of(new CredentialItem("raw-1")), null, null, null);
        var stored = credential();
        when(storeCredentialWorkflow.storeCredential(USER_ID, "raw-1", "dc+sd-jwt", "cfg-1", "", Map.of(), null))
                .thenReturn(Mono.just(stored));

        // Act
        var result = controller.finalizeIssuance(request, auth);

        // Assert
        StepVerifier.create(result).expectNextCount(1).verifyComplete();
    }

    @Test
    void finalizeIssuance_responseWithoutCredentials_failsBeforeStoring() {
        // Arrange
        var request = request(List.of(), null, null, null);

        // Act + Assert
        assertThatThrownBy(() -> controller.finalizeIssuance(request, auth))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("No credential found in credential response");
        verifyNoInteractions(storeCredentialWorkflow);
    }

    @Test
    void extractCredentialRaw_missingNestedObjects_failsWithIllegalArgument() {
        // Arrange
        var noWrapper = new FinalizeIssuanceRequest(null, "dc+sd-jwt", "cfg-1", null, null, null);
        var noResponse = new FinalizeIssuanceRequest(new CredentialResponseWithStatus(null),
                "dc+sd-jwt", "cfg-1", null, null, null);
        var noList = new FinalizeIssuanceRequest(new CredentialResponseWithStatus(new CredentialResponse(null)),
                "dc+sd-jwt", "cfg-1", null, null, null);

        // Act + Assert
        assertThatThrownBy(noWrapper::extractCredentialRaw).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(noResponse::extractCredentialRaw).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(noList::extractCredentialRaw).isInstanceOf(IllegalArgumentException.class);
    }

    private static FinalizeIssuanceRequest request(List<CredentialItem> items, Map<String, Object> metadata,
                                                   String holderKeyId, String holderKid) {
        return new FinalizeIssuanceRequest(
                new CredentialResponseWithStatus(new CredentialResponse(items)),
                "dc+sd-jwt", "cfg-1", metadata, holderKeyId, holderKid);
    }

    private static WalletCredential credential() {
        var now = Instant.now();
        return new WalletCredential(UUID.randomUUID(), USER_ID, "raw-1", CredentialFormat.DC_SD_JWT, "cfg-1", "",
                "Type", null, "https://issuer", "did:sub", now, null, CredentialStatus.VALID, Map.of(), "hk-1", now, now);
    }
}
