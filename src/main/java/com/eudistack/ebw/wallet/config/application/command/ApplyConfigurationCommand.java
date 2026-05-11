package com.eudistack.ebw.wallet.config.application.command;

import com.eudistack.ebw.wallet.config.domain.model.KeyManager;
import com.eudistack.ebw.wallet.config.domain.model.WalletMode;

import java.util.Optional;

/**
 * Immutable command carrying all inputs required to create or update a tenant wallet configuration.
 *
 * <p>This record is the boundary object between the infrastructure layer (controller)
 * and the application layer ({@code TenantWalletConfigurationWriter}). It contains no
 * validation logic — validation happens at the controller boundary (HTTP layer) and
 * invariant enforcement happens in {@code TenantWalletConfigInvariants}.
 *
 * @param schemaName      the PostgreSQL schema name that uniquely identifies the tenant
 * @param host            the public hostname of the tenant (e.g. {@code acme.eudiw.example.com});
 *                        expected to be normalised to lowercase by the caller before construction
 * @param walletMode      the requested wallet operating mode; must not be {@code null}
 * @param keyManager      the key management backend; absent for BROWSER-mode tenants (FR-20)
 * @param expectedVersion optional optimistic-lock version: when present and the tenant already
 *                        exists, the write only succeeds if the stored version matches (otherwise
 *                        a {@code ConfigVersionConflictException} → HTTP 409). {@code null} means
 *                        "create, or update unconditionally".
 * @param actor           identifier of the user or service that issued the command
 *                        (recorded verbatim in the audit log)
 * @param correlationId   optional trace/correlation identifier; if blank, the writer generates one
 */
public record ApplyConfigurationCommand(
        String schemaName,
        String host,
        WalletMode walletMode,
        Optional<KeyManager> keyManager,
        Long expectedVersion,
        String actor,
        String correlationId) {
}
