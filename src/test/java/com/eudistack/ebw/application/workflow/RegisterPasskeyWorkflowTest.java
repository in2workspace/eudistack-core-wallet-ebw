package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.exception.DuplicatePasskeyException;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.AuthTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class RegisterPasskeyWorkflowTest {

    private UserPasskeyRepository passkeyRepository;
    private AuditService auditService;
    private AuthTokenService authTokenService;
    private RegisterPasskeyWorkflow workflow;

    private UUID userId;

    @BeforeEach
    void setUp() {
        passkeyRepository = mock(UserPasskeyRepository.class);
        auditService = mock(AuditService.class);
        authTokenService = mock(AuthTokenService.class);
        workflow = new RegisterPasskeyWorkflow(passkeyRepository, auditService, authTokenService);

        userId = UUID.randomUUID();
        when(passkeyRepository.findByUserIdAndCredentialId(any(), any())).thenReturn(Mono.empty());
        when(passkeyRepository.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());
    }

    @Test
    void registerPasskey_duplicateCredentialForUser_throwsDuplicatePasskeyException() {
        // Arrange
        when(passkeyRepository.findByUserIdAndCredentialId(userId, "cred-1"))
                .thenReturn(Mono.just(UserPasskey.create(userId, "cred-1", "Old", "ua")));

        // Act
        var result = workflow.registerPasskey(userId, "cred-1", "New Name", "ua", null);

        // Assert
        StepVerifier.create(result)
                .expectError(DuplicatePasskeyException.class)
                .verify();
        verify(passkeyRepository, never()).save(any());
    }

    @Test
    void registerPasskey_withRefreshToken_linksTheSessionToTheNewPasskey() {
        // Arrange
        when(authTokenService.linkSessionToPasskey(eq("raw-refresh-token"), eq(userId), any()))
                .thenReturn(Mono.empty());

        // Act
        var result = workflow.registerPasskey(userId, "cred-1", "My PC", "ua", "raw-refresh-token");

        // Assert
        StepVerifier.create(result)
                .assertNext(passkey -> {
                    assertThat(passkey.getCredentialId()).isEqualTo("cred-1");
                    assertThat(passkey.getDisplayName()).isEqualTo("My PC");
                })
                .verifyComplete();
        verify(authTokenService).linkSessionToPasskey(eq("raw-refresh-token"), eq(userId), any());
    }

    @Test
    void registerPasskey_withoutRefreshToken_skipsLinkingAltogether() {
        // Act
        var result = workflow.registerPasskey(userId, "cred-1", "My PC", "ua", null);

        // Assert
        StepVerifier.create(result)
                .expectNextCount(1)
                .verifyComplete();
        verify(authTokenService, never()).linkSessionToPasskey(any(), any(), any());
    }

    @Test
    void registerPasskey_linkingFails_stillReturnsTheCreatedPasskey() {
        // Arrange: linking is best-effort bookkeeping — a stale/rotated refresh token must
        // never cause passkey creation itself to fail (EUD-104 R-3-style guarantee).
        when(authTokenService.linkSessionToPasskey(any(), any(), any()))
                .thenReturn(Mono.error(new RuntimeException("token already rotated")));

        // Act
        var result = workflow.registerPasskey(userId, "cred-1", "My PC", "ua", "stale-token");

        // Assert
        StepVerifier.create(result)
                .expectNextCount(1)
                .verifyComplete();
    }
}
