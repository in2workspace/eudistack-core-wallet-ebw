package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc;

import java.time.Instant;

/**
 * R2DBC row-mapping POJO for the {@code hybrid_wrapped_key_handle} table.
 *
 * <p>This class is used exclusively by {@code DatabaseClient} raw-SQL mappings. Spring
 * Data's {@code ReactiveCrudRepository} is not used because the table has a composite
 * primary key ({@code holder_id, credential_id}), which Spring Data R2DBC does not support
 * natively (AD-4, technical-design.md §3.2).</p>
 *
 * <p>Mapping from rows to the domain model is done in
 * {@link com.eudistack.ebw.keymanager.application.EnrollHolderUseCase}'s R2DBC adapter.
 * The {@code cnf_jwk} column is stored as {@code TEXT}; no JSON codec is required here.</p>
 *
 * <p>Spec: EUDISTACK-534 T4; architecture.md §5.3.</p>
 */
public class WrappedKeyHandleRow {

    private String holderId;
    private String credentialId;
    private byte[] wrappedBlob;
    private byte[] iv;
    private byte[] tag;
    private String kdfAlgo;
    private int kdfVersion;
    private String cnfJwk;
    private Instant createdAt;
    private Instant lastUsedAt;

    public String getHolderId() { return holderId; }
    public void setHolderId(String holderId) { this.holderId = holderId; }

    public String getCredentialId() { return credentialId; }
    public void setCredentialId(String credentialId) { this.credentialId = credentialId; }

    public byte[] getWrappedBlob() { return wrappedBlob; }
    public void setWrappedBlob(byte[] wrappedBlob) { this.wrappedBlob = wrappedBlob; }

    public byte[] getIv() { return iv; }
    public void setIv(byte[] iv) { this.iv = iv; }

    public byte[] getTag() { return tag; }
    public void setTag(byte[] tag) { this.tag = tag; }

    public String getKdfAlgo() { return kdfAlgo; }
    public void setKdfAlgo(String kdfAlgo) { this.kdfAlgo = kdfAlgo; }

    public int getKdfVersion() { return kdfVersion; }
    public void setKdfVersion(int kdfVersion) { this.kdfVersion = kdfVersion; }

    public String getCnfJwk() { return cnfJwk; }
    public void setCnfJwk(String cnfJwk) { this.cnfJwk = cnfJwk; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getLastUsedAt() { return lastUsedAt; }
    public void setLastUsedAt(Instant lastUsedAt) { this.lastUsedAt = lastUsedAt; }
}