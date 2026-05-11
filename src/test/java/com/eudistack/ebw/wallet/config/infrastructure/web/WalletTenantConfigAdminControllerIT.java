package com.eudistack.ebw.wallet.config.infrastructure.web;

import com.eudistack.ebw.wallet.config.application.command.ApplyConfigurationCommand;
import com.eudistack.ebw.wallet.config.application.workflow.TenantWalletConfigurationWriter;
import com.eudistack.ebw.wallet.config.domain.exception.ConfigInvariantViolationException;
import com.eudistack.ebw.wallet.config.domain.model.TenantWalletConfigDescriptor;
import com.eudistack.ebw.wallet.config.domain.model.WalletMode;
import com.eudistack.ebw.wallet.config.infrastructure.controller.WalletTenantConfigAdminController;
import com.eudistack.ebw.wallet.config.infrastructure.controller.dto.AdminConfigRequestDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Collections;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Controller unit tests for {@link WalletTenantConfigAdminController}.
 *
 * <p>Covers T-8 (AC-2c — 201 for valid browser request) and T-13 (AC-2a — 409 for
 * browser + key_manager) from tech-design §2.3.
 *
 * <p>Tests the controller's HTTP contract at the method level (without a running WebFlux
 * context), verifying: status codes, invariant violation error format (RFC 9457 with
 * {@code conflicting_field}), and delegation to the writer.
 *
 * <p>Tagged {@code integration} per tech-design §2.3 test matrix (T-8, T-13).
 */
@ExtendWith(MockitoExtension.class)
@Tag("integration")
class WalletTenantConfigAdminControllerIT {

    @Mock
    TenantWalletConfigurationWriter writer;

    WalletTenantConfigAdminController controller;

    @BeforeEach
    void setUp() {
        controller = new WalletTenantConfigAdminController(writer);
    }

    // ------------------------------------------------------------------
    // T-8: create() with wallet_mode=browser, key_manager=null → 201 (AC-2c)
    // ------------------------------------------------------------------

    /**
     * T-8: Valid BROWSER-mode request with {@code key_manager=null} → HTTP 201 Created.
     *
     * <p>Verifies:
     * <ul>
     *   <li>Response status 201.</li>
     *   <li>Writer is called (delegate works).</li>
     *   <li>Response body is the persisted descriptor.</li>
     * </ul>
     */
    @Test
    void postBrowserWithNullKeyManagerReturns201() {
        // Given
        TenantWalletConfigDescriptor savedDescriptor = TenantWalletConfigDescriptor.of(
                "acme_bw", "acme-admin.eudiw.example.com",
                WalletMode.BROWSER, Optional.empty(), false, Collections.emptyList(), 1L);
        when(writer.applyConfiguration(any(ApplyConfigurationCommand.class)))
                .thenReturn(Mono.just(savedDescriptor));

        AdminConfigRequestDto request = new AdminConfigRequestDto(
                "acme_bw", "acme-admin.eudiw.example.com", "browser", null, false, null);

        // When
        Mono<ResponseEntity<Object>> result = controller.create(request, null, null);

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
                    assertThat(response.getBody()).isNotNull();
                })
                .verifyComplete();
    }

    // ------------------------------------------------------------------
    // T-13: create() with wallet_mode=browser, key_manager=db-tde → 409 RFC 9457 (AC-2a)
    // ------------------------------------------------------------------

    /**
     * T-13: BROWSER + non-null {@code key_manager} → HTTP 409 Conflict with RFC 9457 body.
     *
     * <p>The writer signals a {@link ConfigInvariantViolationException} (domain-layer
     * enforcement). The controller catches it via {@code onErrorResume} and maps to 409.
     *
     * <p>Verifies:
     * <ul>
     *   <li>Response status 409.</li>
     *   <li>Body is a {@link ProblemDetail} with
     *       {@code type=urn:eudistack:error:config-invariant-violation}.</li>
     *   <li>Body extension property {@code conflicting_field} is {@code key_manager} (AC-2a).</li>
     * </ul>
     */
    @Test
    void postBrowserWithKeyManagerReturns409() {
        // Given: writer throws invariant violation
        ConfigInvariantViolationException ex =
                new ConfigInvariantViolationException("key_manager", "db-tde");
        when(writer.applyConfiguration(any(ApplyConfigurationCommand.class)))
                .thenReturn(Mono.error(ex));

        AdminConfigRequestDto request = new AdminConfigRequestDto(
                "conflict_bw", "conflict.eudiw.example.com", "browser", "db-tde", false, null);

        // When
        Mono<ResponseEntity<Object>> result = controller.create(request, null, null);

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);

                    var problem = (ProblemDetail) response.getBody();
                    assertThat(problem).isNotNull();
                    assertThat(problem.getType().toString())
                            .isEqualTo("urn:eudistack:error:config-invariant-violation");
                    assertThat(problem.getStatus()).isEqualTo(409);
                    // AC-2a: conflicting_field must identify key_manager
                    assertThat(problem.getProperties())
                            .containsEntry("conflicting_field", "key_manager");
                })
                .verifyComplete();
    }

    // ------------------------------------------------------------------
    // AC-2b: hybrid key_manager with browser mode → 409
    // ------------------------------------------------------------------

    /**
     * AC-2b variant: BROWSER + {@code key_manager=hybrid} → HTTP 409 Conflict.
     */
    @Test
    void postBrowserWithHybridKeyManagerReturns409() {
        // Given
        ConfigInvariantViolationException ex =
                new ConfigInvariantViolationException("key_manager", "hybrid");
        when(writer.applyConfiguration(any(ApplyConfigurationCommand.class)))
                .thenReturn(Mono.error(ex));

        AdminConfigRequestDto request = new AdminConfigRequestDto(
                "hybrid_bw", "hybrid.eudiw.example.com", "browser", "hybrid", false, null);

        // When
        Mono<ResponseEntity<Object>> result = controller.create(request, null, null);

        // Then
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
                    var problem = (ProblemDetail) response.getBody();
                    assertThat(problem.getProperties())
                            .containsEntry("conflicting_field", "key_manager");
                })
                .verifyComplete();
    }
}
