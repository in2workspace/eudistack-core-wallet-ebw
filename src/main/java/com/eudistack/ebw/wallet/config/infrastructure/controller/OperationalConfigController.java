package com.eudistack.ebw.wallet.config.infrastructure.controller;

import com.eudistack.ebw.wallet.config.application.operational.OperationalConfigReader;
import com.eudistack.ebw.wallet.config.application.operational.OperationalConfigWriter;
import com.eudistack.ebw.wallet.config.infrastructure.controller.dto.OperationalConfigRequestDto;
import com.eudistack.ebw.wallet.config.infrastructure.controller.dto.OperationalConfigResponseDto;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
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
 * Admin controller for the per-tenant operational configuration plane.
 *
 * <p>Exposes three endpoints under
 * {@code /business-wallet/admin/wallet-operational-config}, all protected by PBAC
 * ({@code tenant.config.write}) and DPoP (enforced by existing security filters):
 * <ul>
 *   <li>{@code POST} — create the operational configuration for the current tenant;
 *       returns {@code 201 Created} with the persisted descriptor and an {@code ETag}
 *       header set to {@code "<version>"}.</li>
 *   <li>{@code PUT} — update the configuration using optimistic concurrency control;
 *       requires an {@code If-Match: "<N>"} header ({@code 428 Precondition Required}
 *       if absent; {@code 412 Precondition Failed} if the version has changed).</li>
 *   <li>{@code GET} — retrieve the active configuration; {@code 200 OK} if present,
 *       {@code 404 Not Found} if no active configuration exists yet.</li>
 * </ul>
 *
 * <p>Security invariants:
 * <ul>
 *   <li>The response body never includes {@code wrapped_dek} or {@code column_encryption_key_arn}
 *       (AC-2c).</li>
 *   <li>The actor (PBAC subject) is resolved from the reactive security context, not from
 *       the request body — the caller cannot impersonate another principal.</li>
 *   <li>The {@code correlation_id} is taken from {@code X-Correlation-Id} header if present,
 *       or a UUID v4 is generated; it appears in audit events and server logs but never in
 *       response bodies.</li>
 * </ul>
 *
 * <p>Exception mapping is delegated to
 * {@link com.eudistack.ebw.wallet.config.infrastructure.controller.exception.OperationalConfigExceptionHandler}
 * (scoped {@code @RestControllerAdvice} — AD-1).
 */
@RestController
@RequestMapping("/business-wallet/admin/wallet-operational-config")
public class OperationalConfigController {

    private static final Logger log = LoggerFactory.getLogger(OperationalConfigController.class);

    private static final String CORRELATION_ID_HEADER = "X-Correlation-Id";

    private final OperationalConfigWriter writer;
    private final OperationalConfigReader reader;

    public OperationalConfigController(
            OperationalConfigWriter writer,
            OperationalConfigReader reader) {
        this.writer = writer;
        this.reader = reader;
    }

    /**
     * Creates the operational configuration for the current tenant.
     *
     * <ul>
     *   <li>{@code 201 Created} — configuration persisted; body is an
     *       {@link OperationalConfigResponseDto}; {@code ETag: "<version>"} header set.</li>
     *   <li>{@code 400 Bad Request} — invalid field (e.g. malformed ARN, unsupported algorithm).</li>
     *   <li>{@code 409 Conflict} — configuration already exists (use PUT) or unsupported
     *       {@code key_manager}.</li>
     *   <li>{@code 424 Failed Dependency} — KMS connectivity probe failed.</li>
     * </ul>
     *
     * @param body          the operational configuration payload (validated)
     * @param correlationId optional {@code X-Correlation-Id} header; a UUID v4 is generated if absent
     * @return a reactive response entity
     */
    @PostMapping
    public Mono<ResponseEntity<OperationalConfigResponseDto>> create(
            @Valid @RequestBody OperationalConfigRequestDto body,
            @RequestHeader(value = CORRELATION_ID_HEADER, required = false) String correlationId) {

        String resolvedCorrelationId = resolveCorrelationId(correlationId);
        log.info("POST operational-config: keyManager={}, correlationId={}",
                body.keyManager(), resolvedCorrelationId);

        return resolveActor()
                .flatMap(actor -> writer.apply(
                        body.toCommand(actor, resolvedCorrelationId, Optional.empty())))
                .map(descriptor -> {
                    OperationalConfigResponseDto dto = OperationalConfigResponseDto.from(descriptor);
                    String etag = "\"" + descriptor.version() + "\"";
                    return ResponseEntity
                            .status(HttpStatus.CREATED)
                            .header(HttpHeaders.ETAG, etag)
                            .body(dto);
                });
    }

    /**
     * Updates the operational configuration for the current tenant using optimistic concurrency.
     *
     * <p>The {@code If-Match} header is required; its value must be a quoted long integer matching
     * the current {@code version} field (e.g. {@code If-Match: "3"}). Malformed or absent values
     * are rejected before the writer is invoked.
     *
     * <ul>
     *   <li>{@code 200 OK} — configuration updated; body and {@code ETag} set to the new version.</li>
     *   <li>{@code 400 Bad Request} — malformed {@code If-Match} or invalid body field.</li>
     *   <li>{@code 409 Conflict} — unsupported {@code key_manager} or incomplete body.</li>
     *   <li>{@code 412 Precondition Failed} — version mismatch (concurrent update).</li>
     *   <li>{@code 424 Failed Dependency} — KMS probe failed.</li>
     *   <li>{@code 428 Precondition Required} — {@code If-Match} header absent.</li>
     * </ul>
     *
     * @param body          the operational configuration payload (validated)
     * @param ifMatch       the {@code If-Match} header value; required for PUT
     * @param correlationId optional {@code X-Correlation-Id} header
     * @return a reactive response entity
     */
    @PutMapping
    public Mono<ResponseEntity<OperationalConfigResponseDto>> update(
            @Valid @RequestBody OperationalConfigRequestDto body,
            @RequestHeader(value = HttpHeaders.IF_MATCH, required = false) String ifMatch,
            @RequestHeader(value = CORRELATION_ID_HEADER, required = false) String correlationId) {

        if (ifMatch == null) {
            log.debug("PUT rejected: missing If-Match header");
            return Mono.just(ResponseEntity.status(HttpStatus.PRECONDITION_REQUIRED)
                    .<OperationalConfigResponseDto>build());
        }

        Optional<Long> ifMatchVersion = parseIfMatch(ifMatch);
        if (ifMatchVersion.isEmpty()) {
            log.debug("PUT rejected: malformed If-Match header value='{}'", ifMatch);
            return Mono.error(new IllegalArgumentException(
                    "If-Match header must be a quoted long integer (e.g. \"3\"); received: " + ifMatch));
        }

        String resolvedCorrelationId = resolveCorrelationId(correlationId);
        log.info("PUT operational-config: keyManager={}, ifMatch={}, correlationId={}",
                body.keyManager(), ifMatchVersion.get(), resolvedCorrelationId);

        return resolveActor()
                .flatMap(actor -> writer.apply(
                        body.toCommand(actor, resolvedCorrelationId, ifMatchVersion)))
                .map(descriptor -> {
                    OperationalConfigResponseDto dto = OperationalConfigResponseDto.from(descriptor);
                    String etag = "\"" + descriptor.version() + "\"";
                    return ResponseEntity.ok()
                            .header(HttpHeaders.ETAG, etag)
                            .body(dto);
                });
    }

    /**
     * Retrieves the currently active operational configuration for the current tenant.
     *
     * <ul>
     *   <li>{@code 200 OK} — active configuration present; body and {@code ETag} set.</li>
     *   <li>{@code 404 Not Found} — no active configuration has been applied yet.</li>
     * </ul>
     *
     * @param correlationId optional {@code X-Correlation-Id} header
     * @return a reactive response entity
     */
    @GetMapping
    public Mono<ResponseEntity<OperationalConfigResponseDto>> retrieve(
            @RequestHeader(value = CORRELATION_ID_HEADER, required = false) String correlationId) {

        String resolvedCorrelationId = resolveCorrelationId(correlationId);
        log.debug("GET operational-config: correlationId={}", resolvedCorrelationId);

        return reader.findActive()
                .flatMap(optDescriptor -> {
                    if (optDescriptor.isEmpty()) {
                        log.debug("GET operational-config: no active config found, correlationId={}",
                                resolvedCorrelationId);
                        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.NOT_FOUND);
                        problem.setType(URI.create("urn:eudistack:error:operational-config-not-found"));
                        problem.setTitle("Not Found");
                        problem.setDetail("No active operational configuration has been applied for this tenant.");
                        return Mono.<ResponseEntity<OperationalConfigResponseDto>>just(
                                ResponseEntity.status(HttpStatus.NOT_FOUND).build());
                    }
                    var descriptor = optDescriptor.get();
                    OperationalConfigResponseDto dto = OperationalConfigResponseDto.from(descriptor);
                    String etag = "\"" + descriptor.version() + "\"";
                    return Mono.just(ResponseEntity.ok()
                            .header(HttpHeaders.ETAG, etag)
                            .body(dto));
                });
    }

    // --- Private helpers ---

    /**
     * Resolves the authenticated principal name from the reactive security context.
     *
     * <p>The EBW's {@code JwtAuthenticationWebFilter} places a {@link
     * com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken} in the context for
     * every authenticated request. {@code getName()} returns the string representation of
     * the user's UUID, which is used as the {@code actor} in audit events.
     *
     * <p>If no authentication is present (e.g. in unit tests not using WebFlux security), the
     * chain returns a safe fallback. In production, the PBAC filter rejects unauthenticated
     * requests before reaching this method.
     */
    private Mono<String> resolveActor() {
        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication().getName())
                .defaultIfEmpty("anonymous");
    }

    /**
     * Returns the {@code X-Correlation-Id} value if present and non-blank,
     * or generates a UUID v4.
     */
    private static String resolveCorrelationId(String correlationId) {
        if (correlationId != null && !correlationId.isBlank()) {
            return correlationId;
        }
        return UUID.randomUUID().toString();
    }

    /**
     * Parses the {@code If-Match} header value into an {@link Optional} long.
     *
     * <p>The header value must be a quoted long integer per RFC 9110 §8.8.3,
     * e.g. {@code "3"}. Leading and trailing {@code "} characters are stripped before parsing.
     *
     * @param ifMatch the raw {@code If-Match} header value
     * @return {@link Optional#of(Object)} with the parsed version, or
     *         {@link Optional#empty()} if the value is malformed
     */
    private static Optional<Long> parseIfMatch(String ifMatch) {
        if (ifMatch == null || ifMatch.isBlank()) {
            return Optional.empty();
        }
        // Strip surrounding quotes: "3" → 3
        String stripped = ifMatch.trim();
        if (stripped.startsWith("\"") && stripped.endsWith("\"") && stripped.length() > 1) {
            stripped = stripped.substring(1, stripped.length() - 1);
        }
        try {
            return Optional.of(Long.parseLong(stripped));
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }
}
