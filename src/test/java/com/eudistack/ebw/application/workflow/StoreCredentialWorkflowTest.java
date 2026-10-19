package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.CredentialFormat;
import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.model.WalletCredential;
import com.eudistack.ebw.domain.model.exception.UnsupportedFormatException;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.CredentialService;
import com.eudistack.ebw.domain.service.CredentialService.ParsedCredential;
import com.eudistack.ebw.domain.service.TenantConfigService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link StoreCredentialWorkflow} — format allowlist per tenant, parse, insert and audit.
 */
@ExtendWith(MockitoExtension.class)
class StoreCredentialWorkflowTest {

    private static final UUID USER_ID = UUID.randomUUID();
    private static final String ALLOWED_FORMATS_KEY = "ebw.allowed_credential_formats";
    private static final String DEFAULT_ALLOWED_FORMATS = "dc+sd-jwt,jwt_vc_json";
    private static final String RAW = "eyJ.raw.credential~";
    private static final Map<String, Object> ISSUER_METADATA = Map.of("credential_issuer", "https://issuer");

    @Mock private CredentialService credentialService;
    @Mock private TenantConfigService tenantConfigService;
    @Mock private WalletCredentialRepository credentialRepository;
    @Mock private AuditService auditService;

    private StoreCredentialWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new StoreCredentialWorkflow(credentialService, tenantConfigService, credentialRepository, auditService);
    }

    @Test
    void storeCredential_formatInTenantAllowlist_insertsCredentialAndRecordsAudit() {
        // Arrange
        var issuance = Instant.parse("2026-01-01T00:00:00Z");
        var expiration = Instant.parse("2027-01-01T00:00:00Z");
        when(credentialService.validateFormat("dc+sd-jwt")).thenReturn(CredentialFormat.DC_SD_JWT);
        when(tenantConfigService.getStringOrDefault(ALLOWED_FORMATS_KEY, DEFAULT_ALLOWED_FORMATS))
                .thenReturn(Mono.just(" jwt_vc_json , DC+SD-JWT "));
        when(credentialService.parseCredential(RAW, CredentialFormat.DC_SD_JWT))
                .thenReturn(Mono.just(new ParsedCredential("https://issuer", "did:sub", issuance, expiration,
                        "LEARCredentialEmployee", "urn:vct:lear")));
        when(credentialRepository.insert(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        when(credentialService.computeAuditHash(RAW)).thenReturn("abc123");
        when(auditService.record(eq("credential"), any(), eq("CREATED"), eq(USER_ID), any())).thenReturn(Mono.empty());

        // Act
        var result = workflow.storeCredential(USER_ID, RAW, "dc+sd-jwt", "cfg-1", "kid-1", ISSUER_METADATA, "hk-1");

        // Assert
        StepVerifier.create(result)
                .assertNext(saved -> {
                    assertThat(saved.getUserId()).isEqualTo(USER_ID);
                    assertThat(saved.getCredentialRaw()).isEqualTo(RAW);
                    assertThat(saved.getFormat()).isEqualTo(CredentialFormat.DC_SD_JWT);
                    assertThat(saved.getCredentialConfigId()).isEqualTo("cfg-1");
                    assertThat(saved.getKid()).isEqualTo("kid-1");
                    assertThat(saved.getCredentialType()).isEqualTo("LEARCredentialEmployee");
                    assertThat(saved.getVct()).isEqualTo("urn:vct:lear");
                    assertThat(saved.getIssuer()).isEqualTo("https://issuer");
                    assertThat(saved.getSubject()).isEqualTo("did:sub");
                    assertThat(saved.getIssuanceDate()).isEqualTo(issuance);
                    assertThat(saved.getExpirationDate()).isEqualTo(expiration);
                    assertThat(saved.getStatus()).isEqualTo(CredentialStatus.VALID);
                    assertThat(saved.getIssuerMetadata()).isEqualTo(ISSUER_METADATA);
                    assertThat(saved.getHolderKeyId()).isEqualTo("hk-1");
                })
                .verifyComplete();
        verify(auditService).record(eq("credential"), any(), eq("CREATED"), eq(USER_ID),
                eq(Map.of("entity_hash", "sha256:abc123", "format", "dc+sd-jwt",
                        "credential_type", "LEARCredentialEmployee")));
    }

    @Test
    void storeCredential_tenantAllowsEveryFormat_skipsAllowlistCheck() {
        // Arrange
        when(credentialService.validateFormat("jwt_vc_json")).thenReturn(CredentialFormat.JWT_VC_JSON);
        when(tenantConfigService.getStringOrDefault(ALLOWED_FORMATS_KEY, DEFAULT_ALLOWED_FORMATS))
                .thenReturn(Mono.just("*"));
        when(credentialService.parseCredential(RAW, CredentialFormat.JWT_VC_JSON))
                .thenReturn(Mono.just(new ParsedCredential("iss", "sub", Instant.now(), null, "Type", null)));
        when(credentialRepository.insert(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        when(credentialService.computeAuditHash(RAW)).thenReturn("h");
        when(auditService.record(anyString(), any(), anyString(), any(), any())).thenReturn(Mono.empty());

        // Act
        var result = workflow.storeCredential(USER_ID, RAW, "jwt_vc_json", "cfg", null, Map.of(), null);

        // Assert
        StepVerifier.create(result)
                .assertNext(saved -> assertThat(saved.getFormat()).isEqualTo(CredentialFormat.JWT_VC_JSON))
                .verifyComplete();
    }

    @Test
    void storeCredential_formatNotInTenantAllowlist_failsWithUnsupportedFormatWithoutParsing() {
        // Arrange
        when(credentialService.validateFormat("jwt_vc_json")).thenReturn(CredentialFormat.JWT_VC_JSON);
        when(tenantConfigService.getStringOrDefault(ALLOWED_FORMATS_KEY, DEFAULT_ALLOWED_FORMATS))
                .thenReturn(Mono.just("dc+sd-jwt"));

        // Act
        var result = workflow.storeCredential(USER_ID, RAW, "jwt_vc_json", "cfg", null, Map.of(), null);

        // Assert
        StepVerifier.create(result)
                .expectError(UnsupportedFormatException.class)
                .verify();
        verify(credentialService, never()).parseCredential(anyString(), any());
        verify(credentialRepository, never()).insert(any());
    }

    @Test
    void storeCredential_unknownFormat_failsWithUnsupportedFormatBeforeReadingTenantConfig() {
        // Arrange
        when(credentialService.validateFormat("mso_mdoc")).thenThrow(new UnsupportedFormatException("mso_mdoc"));

        // Act
        var result = workflow.storeCredential(USER_ID, RAW, "mso_mdoc", "cfg", null, Map.of(), null);

        // Assert
        StepVerifier.create(result)
                .expectError(UnsupportedFormatException.class)
                .verify();
        verify(tenantConfigService, never()).getStringOrDefault(anyString(), anyString());
    }

    @Test
    void storeCredential_insertFails_propagatesErrorAndSkipsAudit() {
        // Arrange
        when(credentialService.validateFormat("dc+sd-jwt")).thenReturn(CredentialFormat.DC_SD_JWT);
        when(tenantConfigService.getStringOrDefault(ALLOWED_FORMATS_KEY, DEFAULT_ALLOWED_FORMATS))
                .thenReturn(Mono.just(DEFAULT_ALLOWED_FORMATS));
        when(credentialService.parseCredential(RAW, CredentialFormat.DC_SD_JWT))
                .thenReturn(Mono.just(new ParsedCredential("iss", "sub", Instant.now(), null, "Type", "vct")));
        when(credentialRepository.insert(any(WalletCredential.class)))
                .thenReturn(Mono.error(new IllegalStateException("db down")));

        // Act
        var result = workflow.storeCredential(USER_ID, RAW, "dc+sd-jwt", "cfg", null, Map.of(), null);

        // Assert
        StepVerifier.create(result)
                .expectErrorMessage("db down")
                .verify();
        verify(auditService, never()).record(anyString(), any(), anyString(), any(), any());
    }
}
