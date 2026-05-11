package com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * R2DBC entity for the {@code public.tenant_wallet_config} table.
 *
 * <p>Follows the {@link Persistable} pattern used across the EBW codebase
 * to handle INSERT vs UPDATE correctly with Spring Data R2DBC.
 *
 * <p>The {@code keyManager} column is nullable — BROWSER-mode tenants always
 * have {@code key_manager = NULL} (invariant FR-20).
 */
@Table("public.tenant_wallet_config")
public class WalletTenantConfigEntity implements Persistable<String> {

    @Id
    private String schemaName;
    private String host;
    private String walletMode;
    private String keyManager;
    private boolean naturalPersonsOnly;
    private long version;
    private String updatedBy;
    private Instant updatedAt;

    @Transient
    private boolean isNew = false;

    public WalletTenantConfigEntity() {}

    @Override
    public String getId() {
        return schemaName;
    }

    @Override
    public boolean isNew() {
        return isNew;
    }

    public void markNew() {
        this.isNew = true;
    }

    public String getSchemaName() {
        return schemaName;
    }

    public void setSchemaName(String schemaName) {
        this.schemaName = schemaName;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getWalletMode() {
        return walletMode;
    }

    public void setWalletMode(String walletMode) {
        this.walletMode = walletMode;
    }

    public String getKeyManager() {
        return keyManager;
    }

    public void setKeyManager(String keyManager) {
        this.keyManager = keyManager;
    }

    public boolean isNaturalPersonsOnly() {
        return naturalPersonsOnly;
    }

    public void setNaturalPersonsOnly(boolean naturalPersonsOnly) {
        this.naturalPersonsOnly = naturalPersonsOnly;
    }

    public long getVersion() {
        return version;
    }

    public void setVersion(long version) {
        this.version = version;
    }

    public String getUpdatedBy() {
        return updatedBy;
    }

    public void setUpdatedBy(String updatedBy) {
        this.updatedBy = updatedBy;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }
}
