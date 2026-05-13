package com.eudistack.ebw.wallet.config.infrastructure.adapter.r2dbc.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

/**
 * R2DBC entity for the {@code wallet_operational_config_db_tde} sub-table.
 *
 * <p>1:0..1 relationship with {@link WalletOperationalConfigEntity} via {@code config_id}
 * (PK + FK ON DELETE CASCADE to the root table). Lives in the tenant-scoped schema.
 *
 * <p>The {@code wrappedDek} field contains KMS-encrypted key material (ciphertext).
 * Defensive copies are made on both read and write to prevent mutation of the byte array
 * outside this class. This field is never logged — consumers must treat it as opaque bytes.
 */
@Table("wallet_operational_config_db_tde")
public class WalletOperationalConfigDbTdeEntity {

    @Id
    private UUID configId;
    private String columnEncryptionKeyArn;
    private byte[] wrappedDek;
    private String algorithm;
    private Instant createdAt;

    public WalletOperationalConfigDbTdeEntity() {}

    public UUID getConfigId() {
        return configId;
    }

    public void setConfigId(UUID configId) {
        this.configId = configId;
    }

    public String getColumnEncryptionKeyArn() {
        return columnEncryptionKeyArn;
    }

    public void setColumnEncryptionKeyArn(String columnEncryptionKeyArn) {
        this.columnEncryptionKeyArn = columnEncryptionKeyArn;
    }

    /**
     * Returns a defensive copy of the wrapped DEK bytes.
     * Never pass the returned array to a logger or serialize it in a response body.
     */
    public byte[] getWrappedDek() {
        return wrappedDek == null ? null : Arrays.copyOf(wrappedDek, wrappedDek.length);
    }

    /**
     * Stores a defensive copy of the wrapped DEK bytes.
     */
    public void setWrappedDek(byte[] wrappedDek) {
        this.wrappedDek = wrappedDek == null ? null : Arrays.copyOf(wrappedDek, wrappedDek.length);
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}
