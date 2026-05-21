package com.eudistack.ebw.wallet.profile.infrastructure.adapter.r2dbc.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * R2DBC entity mapping the {@code tenant_wallet_profile} table.
 *
 * <p>The primary key is the {@code tenant} string (AD-412-1): one row per tenant,
 * keyed by the stable tenant identifier. This departs from the surrogate-UUID pattern
 * used by {@code TenantConfigEntity} — the rationale is documented in AD-412-1 of
 * {@code EUDISTACK-412/technical-design.md}.
 *
 * <p>Column values for {@code wallet_mode} and {@code key_manager} are stored as raw
 * strings (matching the PostgreSQL {@code VARCHAR(20)} columns defined in
 * {@code V3__Wallet_profile.sql}). Conversion to the domain enums {@link
 * com.eudistack.ebw.wallet.profile.domain.model.WalletMode} and {@link
 * com.eudistack.ebw.wallet.profile.domain.model.KeyManager} is done inline in the
 * adapter (AD-412-3) — this class carries no domain knowledge.
 *
 * <p>No Lombok — follows the no-Lombok convention established by the existing entities
 * in this repository (e.g. {@code TenantConfigEntity}, {@code WalletUserEntity}).
 */
@Table("tenant_wallet_profile")
public class TenantWalletProfileEntity {

    @Id
    private String tenant;

    @Column("wallet_mode")
    private String walletMode;

    @Column("key_manager")
    private String keyManager;

    @Column("created_at")
    private Instant createdAt;

    @Column("updated_at")
    private Instant updatedAt;

    public TenantWalletProfileEntity() {}

    public TenantWalletProfileEntity(String tenant, String walletMode, String keyManager,
                                     Instant createdAt, Instant updatedAt) {
        this.tenant = tenant;
        this.walletMode = walletMode;
        this.keyManager = keyManager;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    public String getTenant() { return tenant; }
    public void setTenant(String tenant) { this.tenant = tenant; }
    public String getWalletMode() { return walletMode; }
    public void setWalletMode(String walletMode) { this.walletMode = walletMode; }
    public String getKeyManager() { return keyManager; }
    public void setKeyManager(String keyManager) { this.keyManager = keyManager; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}