package com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * R2DBC entity for the {@code wallet_operational_config} root table.
 *
 * <p>Mapped manually via {@code DatabaseClient} row-reads in
 * {@code OperationalConfigR2dbcAdapter}; also used by {@code R2dbcEntityTemplate} for
 * INSERT/UPDATE operations. The table lives in the tenant-scoped schema
 * ({@code <tenant>_business_wallet}) — the {@code search_path} is set by
 * {@code TenantAwareConnectionFactoryDecorator} on every connection (AD-1).
 *
 * <p>One row per {@code key_manager} per tenant. The partial unique index
 * {@code UNIQUE WHERE is_active=true} enforces at most one active row per tenant.
 */
@Table("wallet_operational_config")
public class WalletOperationalConfigEntity {

    @Id
    private UUID id;
    private String keyManager;
    private boolean isActive;
    private String activationStatus;
    private Instant connectivityVerifiedAt;
    private long version;
    private String updatedBy;
    private Instant updatedAt;

    public WalletOperationalConfigEntity() {}

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getKeyManager() {
        return keyManager;
    }

    public void setKeyManager(String keyManager) {
        this.keyManager = keyManager;
    }

    public boolean isActive() {
        return isActive;
    }

    public void setActive(boolean active) {
        isActive = active;
    }

    public String getActivationStatus() {
        return activationStatus;
    }

    public void setActivationStatus(String activationStatus) {
        this.activationStatus = activationStatus;
    }

    public Instant getConnectivityVerifiedAt() {
        return connectivityVerifiedAt;
    }

    public void setConnectivityVerifiedAt(Instant connectivityVerifiedAt) {
        this.connectivityVerifiedAt = connectivityVerifiedAt;
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
