package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.BindWalletInstanceWorkflow;
import com.eudistack.ebw.application.workflow.ListWalletInstancesWorkflow;
import com.eudistack.ebw.application.workflow.RegisterWalletInstanceWorkflow;
import com.eudistack.ebw.application.workflow.RegisterWalletInstanceWorkflow.RegisterCommand;
import com.eudistack.ebw.application.workflow.RenameWalletInstanceWorkflow;
import com.eudistack.ebw.application.workflow.RevokeWalletInstanceWorkflow;
import com.eudistack.ebw.application.workflow.WalletSession;
import com.eudistack.ebw.domain.model.WalletInstance;
import com.eudistack.ebw.domain.model.exception.InvalidSessionException;
import com.eudistack.ebw.domain.model.exception.InvalidWalletInstanceException;
import com.eudistack.ebw.domain.model.exception.RateLimitExceededException;
import com.eudistack.ebw.domain.model.exception.WalletInstanceNotFoundException;
import com.eudistack.ebw.domain.model.exception.WalletInstanceRevokedException;
import com.eudistack.ebw.infrastructure.controller.dto.BindWalletInstanceRequest;
import com.eudistack.ebw.infrastructure.controller.dto.RegisterWalletInstanceRequest;
import com.eudistack.ebw.infrastructure.controller.dto.RenameWalletInstanceRequest;
import com.eudistack.ebw.infrastructure.security.ActiveSessionChecker;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ServerWebInputException;
import org.springframework.web.server.UnsupportedMediaTypeStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link WalletInstanceController} and {@link WalletInstanceProblemExceptionHandler}: the contract of
 * EUD-15 {@code annex/openapi.yaml} (status, body and problem types).
 */
class WalletInstanceControllerTest {

    private RegisterWalletInstanceWorkflow registerWorkflow;
    private BindWalletInstanceWorkflow bindWorkflow;
    private ListWalletInstancesWorkflow listWorkflow;
    private RenameWalletInstanceWorkflow renameWorkflow;
    private RevokeWalletInstanceWorkflow revokeWorkflow;
    private ActiveSessionChecker checker;
    private WalletInstanceController controller;
    private JwtAuthenticationToken auth;
    private WalletInstance current;
    private WalletInstance other;

    @BeforeEach
    void setUp() {
        registerWorkflow = mock(RegisterWalletInstanceWorkflow.class);
        bindWorkflow = mock(BindWalletInstanceWorkflow.class);
        listWorkflow = mock(ListWalletInstancesWorkflow.class);
        renameWorkflow = mock(RenameWalletInstanceWorkflow.class);
        revokeWorkflow = mock(RevokeWalletInstanceWorkflow.class);
        checker = mock(ActiveSessionChecker.class);
        when(checker.forget(any())).thenReturn(Mono.empty());
        controller = new WalletInstanceController(registerWorkflow, bindWorkflow, listWorkflow, renameWorkflow,
                revokeWorkflow, checker);
        var userId = UUID.randomUUID();
        current = WalletInstance.register(userId, "iPhone · App instalada", WalletInstance.DeviceType.MOBILE,
                UUID.randomUUID());
        other = WalletInstance.register(userId, "Mac · Chrome", WalletInstance.DeviceType.DESKTOP, UUID.randomUUID());
        auth = new JwtAuthenticationToken(userId, "ana@example.com", UUID.randomUUID(), UUID.randomUUID(), current.id(),
                List.of());
    }

    @Test
    void list_activeInstances_marksTheCurrentOneWithLowercaseTypes() {
        when(listWorkflow.list(any())).thenReturn(Mono.just(List.of(current, other)));

        StepVerifier.create(controller.list(auth))
                .assertNext(list -> {
                    assertThat(list).extracting(r -> r.current()).containsExactly(true, false);
                    assertThat(list).extracting(r -> r.deviceType()).containsExactly("mobile", "desktop");
                })
                .verifyComplete();
    }

    @Test
    void register_validBody_answers201WithTheInstanceAsCurrentAndForgetsTheCachedSession() {
        when(registerWorkflow.register(any(WalletSession.class), any(RegisterCommand.class))).thenReturn(Mono.just(other));

        StepVerifier.create(controller.register(new RegisterWalletInstanceRequest("Mac · Chrome", "desktop"), auth))
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
                    assertThat(response.getBody().current()).isTrue();
                    assertThat(response.getBody().id()).isEqualTo(other.id());
                })
                .verifyComplete();
        verify(checker).forget(auth.getSessionId());
    }

    @Test
    void bind_rememberedInstance_answersItAsCurrentAndForgetsTheCachedSession() {
        when(bindWorkflow.bind(any(), any())).thenReturn(Mono.just(current));

        StepVerifier.create(controller.bind(new BindWalletInstanceRequest(current.id()), auth))
                .assertNext(response -> assertThat(response.current()).isTrue())
                .verifyComplete();
        verify(checker).forget(auth.getSessionId());
    }

    @Test
    void rename_validName_answersTheRenamedInstance() {
        when(renameWorkflow.rename(any(), any(), any())).thenReturn(Mono.just(other));

        StepVerifier.create(controller.rename(other.id(), new RenameWalletInstanceRequest("Mac · Chrome"), auth))
                .assertNext(response -> assertThat(response.current()).isFalse())
                .verifyComplete();
    }

    @Test
    void revoke_instance_answers204AndForgetsEverySessionItEnded() {
        var ended = UUID.randomUUID();
        when(revokeWorkflow.revoke(any(), any())).thenReturn(Mono.just(List.of(ended)));

        StepVerifier.create(controller.revoke(other.id(), auth))
                .assertNext(response -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT))
                .verifyComplete();
        verify(checker).forget(ended);
    }

    // --- Problems (RFC 9457, type = contract code)

    private final WalletInstanceProblemExceptionHandler handler = new WalletInstanceProblemExceptionHandler();

    @Test
    void problems_eachError_hasItsStatusAndContractType() {
        assertThat(handler.handleInvalidRequest(new InvalidWalletInstanceException("displayName")).getBody().getType())
                .hasToString("invalid_request");
        assertThat(handler.handleInvalidRequest(new ServerWebInputException("bad")).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
        var notFound = handler.handleNotFound(new WalletInstanceNotFoundException());
        assertThat(notFound.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(notFound.getBody().getType()).hasToString("instance_not_found");
        var revoked = handler.handleRevoked(new WalletInstanceRevokedException());
        assertThat(revoked.getStatusCode()).isEqualTo(HttpStatus.GONE);
        assertThat(revoked.getBody().getType()).hasToString("instance_revoked");
        var unexpected = handler.handleUnexpected(new IllegalStateException("ana@example.com"));
        assertThat(unexpected.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(unexpected.getBody().getType()).hasToString("server_error");
        assertThat(unexpected.getBody().getDetail()).isNull();
    }

    @Test
    void problems_accountGoneDuringTheSession_is401InvalidSession() {
        var response = handler.handleInvalidSession(new InvalidSessionException());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody().getType()).hasToString("invalid_session");
    }

    @Test
    void problems_frameworkErrorWithItsOwnStatus_keepsIt() {
        var response = handler.handleResponseStatus(new UnsupportedMediaTypeStatusException("text/plain"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNSUPPORTED_MEDIA_TYPE);
    }

    @Test
    void problems_tooManyRegistrations_is429WithRetryAfter() {
        var response = handler.handleTooManyRequests(new RateLimitExceededException(1200));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(response.getBody().getType()).hasToString("too_many_requests");
        assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("1200");
    }
}
