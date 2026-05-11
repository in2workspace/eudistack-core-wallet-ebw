package com.eudistack.ebw.wallet.config.infrastructure.controller;

import com.eudistack.ebw.wallet.config.application.command.ApplyConfigurationCommand;
import com.eudistack.ebw.wallet.config.application.workflow.TenantWalletConfigurationWriter;
import com.eudistack.ebw.wallet.config.domain.exception.ConfigInvariantViolationException;
import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
import com.eudistack.ebw.wallet.config.domain.model.WalletMode;
import com.eudistack.ebw.wallet.config.infrastructure.controller.dto.AdminConfigRequestDto;
import com.eudistack.ebw.wallet.config.infrastructure.controller.dto.AdminConfigResponseDto;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
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
 * <p><strong>Authorization:</strong> both endpoints require an authenticated principal that
 * carries the {@code tenant.config.write} authority (i.e. a {@code SCOPE_tenant.config.write}
 * granted authority). This is enforced both at the URL level
 * ({@code SecurityConfig#securityWebFilterChain} maps {@code /admin/**}) and at the method level
 * ({@code @PreAuthorize} below) as defence in depth. See SEC-B2 — the auth mechanism that mints
 * an admin-scoped token for DevOps Leads is still to be defined (no such token type exists yet).
 *
 * <p>HTTP 409 Conflict is returned when the domain invariant validator
 * ({@code TenantWalletConfigInvariants}) rejects the {@code walletMode}/{@code keyManager}
 * pairing (AC-2a, AC-2b). The response body follows RFC 9457 with a custom
 * {@code conflicting_field} property.
 *
 * <p>The {@code schemaName} path variable is validated as a strict PostgreSQL identifier
 * ({@code ^[a-z][a-z0-9_]{0,62}$}) — see SEC-B1 — before it ever reaches the persistence or
 * audit adapters.
 */
@RestController
@RequestMapping("/admin/wallet-tenant-config")
public class WalletTenantConfigAdminController {

    /** Strict PostgreSQL identifier pattern, matching {@code AdminConfigRequestDto.schemaName}. */
    private static final String SCHEMA_NAME_PATTERN = "^[a-z][a-z0-9_]{0,62}$";

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
    @PreAuthorize("hasAuthority('SCOPE_tenant.config.write')")
    public Mono<ResponseEntity<Object>> create(
            @Valid @RequestBody AdminConfigRequestDto request,
            Authentication authentication,
            @RequestHeader(value = "X-Correlation-ID", required = false) String correlationId) {

        String actor = resolveActor(authentication);
        String corrId = resolveCorrelationId(correlationId);
        log.debug("Admin create config: schemaName={}, walletMode={}, actor={}",
                request.schemaName(), request.walletMode(), actor);

        // POST is a create — the body's version (if any) is not an optimistic-lock check here.
        ApplyConfigurationCommand command = buildCommand(request, actor, corrId, null);
        return writer.applyConfiguration(command)
                .map(saved -> ResponseEntity.status(HttpStatus.CREATED)
                        .<Object>body(AdminConfigResponseDto.from(saved)))
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
    @PreAuthorize("hasAuthority('SCOPE_tenant.config.write')")
    public Mono<ResponseEntity<Object>> update(
            @PathVariable
            @Pattern(regexp = SCHEMA_NAME_PATTERN,
                    message = "schema_name must be a valid PostgreSQL identifier "
                            + "(lowercase, starts with a letter, max 63 chars)")
            String schemaName,
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

        // On PUT the body's version (when present) is the optimistic-lock expectation (W3).
        ApplyConfigurationCommand command = buildCommand(normalized, actor, corrId, request.version());
        return writer.applyConfiguration(command)
                .map(saved -> ResponseEntity.ok().<Object>body(AdminConfigResponseDto.from(saved)))
                .onErrorResume(ConfigInvariantViolationException.class,
                        ex -> Mono.just(invariantViolationResponse(ex)));
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static ApplyConfigurationCommand buildCommand(
            AdminConfigRequestDto dto, String actor, String correlationId, Long expectedVersion) {
        WalletMode walletMode = WalletMode.fromValue(dto.walletMode());
        Optional<KeyManager> keyManager = dto.keyManager() != null
                ? Optional.of(KeyManager.fromValue(dto.keyManager()))
                : Optional.empty();

        return new ApplyConfigurationCommand(
                dto.schemaName(),
                dto.host().toLowerCase(),
                walletMode,
                keyManager,
                expectedVersion,
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
