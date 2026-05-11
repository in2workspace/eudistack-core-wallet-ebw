package com.eudistack.ebw.wallet.config.infrastructure.controller;

import com.eudistack.ebw.wallet.config.application.command.ApplyConfigurationCommand;
import com.eudistack.ebw.wallet.config.application.workflow.TenantWalletConfigurationWriter;
import com.eudistack.ebw.wallet.config.domain.exception.ConfigInvariantViolationException;
import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
import com.eudistack.ebw.wallet.config.domain.model.TenantWalletConfigDescriptor;
import com.eudistack.ebw.wallet.config.domain.model.WalletMode;
import com.eudistack.ebw.wallet.config.infrastructure.controller.dto.AdminConfigRequestDto;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Optional;
import java.util.UUID;

/**
 * Admin endpoint for creating and updating wallet tenant configurations.
 *
 * <p>Both endpoints require authentication with the {@code tenant.config.write} scope.
 * DPoP token binding is enforced by the upstream JWT filter already installed in the
 * {@link com.eudistack.ebw.infrastructure.configuration.SecurityConfig} filter chain.
 *
 * <p>HTTP 409 Conflict is returned when the domain invariant validator
 * ({@code TenantWalletConfigInvariants}) rejects the {@code walletMode}/{@code keyManager}
 * pairing (AC-2a, AC-2b). The response body follows RFC 9457 with a custom
 * {@code conflicting_field} property.
 */
@RestController
@RequestMapping("/admin/wallet-tenant-config")
public class WalletTenantConfigAdminController {

    private static final Logger log =
            LoggerFactory.getLogger(WalletTenantConfigAdminController.class);

    private final TenantWalletConfigurationWriter writer;

    public WalletTenantConfigAdminController(TenantWalletConfigurationWriter writer) {
        this.writer = writer;
    }

    /**
     * Creates a new wallet tenant configuration.
     *
     * <p>Returns HTTP 201 Created with the persisted descriptor on success.
     * Returns HTTP 409 Conflict if the {@code walletMode}/{@code keyManager} pairing
     * violates an invariant (AC-2).
     *
     * @param request        the configuration request body
     * @param authentication the authenticated principal (for actor extraction)
     * @param correlationId  optional {@code X-Correlation-ID} header for tracing
     * @return a reactive response entity
     */
    @PostMapping
    public Mono<ResponseEntity<Object>> create(
            @Valid @RequestBody AdminConfigRequestDto request,
            Authentication authentication,
            @RequestHeader(value = "X-Correlation-ID", required = false) String correlationId) {

        String actor = resolveActor(authentication);
        String corrId = resolveCorrelationId(correlationId);
        log.debug("Admin create config: schemaName={}, walletMode={}, actor={}",
                request.schemaName(), request.walletMode(), actor);

        ApplyConfigurationCommand command = buildCommand(request, actor, corrId);
        return writer.applyConfiguration(command)
                .map(saved -> ResponseEntity.status(HttpStatus.CREATED)
                        .<Object>body(saved))
                .onErrorResume(ConfigInvariantViolationException.class,
                        ex -> Mono.just(invariantViolationResponse(ex)));
    }

    /**
     * Updates an existing wallet tenant configuration.
     *
     * <p>Returns HTTP 200 OK with the updated descriptor on success.
     * Returns HTTP 409 Conflict if the {@code walletMode}/{@code keyManager} pairing
     * violates an invariant (AC-2).
     *
     * @param schemaName     the tenant schema name from the URL path
     * @param request        the configuration request body
     * @param authentication the authenticated principal (for actor extraction)
     * @param correlationId  optional {@code X-Correlation-ID} header for tracing
     * @return a reactive response entity
     */
    @PutMapping("/{schemaName}")
    public Mono<ResponseEntity<Object>> update(
            @PathVariable String schemaName,
            @Valid @RequestBody AdminConfigRequestDto request,
            Authentication authentication,
            @RequestHeader(value = "X-Correlation-ID", required = false) String correlationId) {

        String actor = resolveActor(authentication);
        String corrId = resolveCorrelationId(correlationId);
        log.debug("Admin update config: schemaName={}, walletMode={}, actor={}",
                schemaName, request.walletMode(), actor);

        // Use path variable schemaName authoritatively (body's schemaName is advisory)
        AdminConfigRequestDto normalized = new AdminConfigRequestDto(
                schemaName,
                request.host(),
                request.walletMode(),
                request.keyManager(),
                request.naturalPersonsOnly(),
                request.version());

        ApplyConfigurationCommand command = buildCommand(normalized, actor, corrId);
        return writer.applyConfiguration(command)
                .map(saved -> ResponseEntity.ok().<Object>body(saved))
                .onErrorResume(ConfigInvariantViolationException.class,
                        ex -> Mono.just(invariantViolationResponse(ex)));
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static ApplyConfigurationCommand buildCommand(
            AdminConfigRequestDto dto, String actor, String correlationId) {
        WalletMode walletMode = WalletMode.fromValue(dto.walletMode());
        Optional<KeyManager> keyManager = dto.keyManager() != null
                ? Optional.of(KeyManager.fromValue(dto.keyManager()))
                : Optional.empty();

        return new ApplyConfigurationCommand(
                dto.schemaName(),
                dto.host().toLowerCase(),
                walletMode,
                keyManager,
                actor,
                correlationId);
    }

    private static String resolveActor(Authentication authentication) {
        if (authentication != null && authentication.getName() != null) {
            return authentication.getName();
        }
        return "unknown";
    }

    private static String resolveCorrelationId(String header) {
        if (header != null && !header.isBlank()) {
            return header;
        }
        return UUID.randomUUID().toString();
    }

    private static ResponseEntity<Object> invariantViolationResponse(
            ConfigInvariantViolationException ex) {
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.CONFLICT);
        problem.setType(URI.create("urn:eudistack:error:config-invariant-violation"));
        problem.setTitle("Invariant violation");
        problem.setDetail(String.format(
                "wallet_mode '%s' is incompatible with key_manager '%s'; "
                        + "received value violates invariant FR-20.",
                "browser", ex.getReceivedValue()));
        problem.setProperty("conflicting_field", ex.getConflictingField());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(problem);
    }
}
