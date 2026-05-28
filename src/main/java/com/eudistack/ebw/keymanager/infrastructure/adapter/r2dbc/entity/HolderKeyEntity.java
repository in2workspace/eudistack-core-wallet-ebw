package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.entity;

import io.r2dbc.postgresql.codec.Json;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

@Table("holder_key")
public class HolderKeyEntity {

    @Id
    @Column("key_id")
    private String keyId;

    @Column("holder_id")
    private String holderId;

    @Column("credential_id")
    private String credentialId;

    @Column("tenant_id")
    private String tenantId;

    @Column("private_key")
    private byte[] privateKey;

    @Column("public_jwk")
    private Json publicJwk;

    @Column("algorithm")
    private String algorithm;

    @Column("format")
    private String format;

    @Column("created_at")
    private Instant createdAt;

    @Column("revoked_at")
    private Instant revokedAt;

    public String getKeyId() { return keyId; }
    public void setKeyId(String keyId) { this.keyId = keyId; }

    public String getHolderId() { return holderId; }
    public void setHolderId(String holderId) { this.holderId = holderId; }

    public String getCredentialId() { return credentialId; }
    public void setCredentialId(String credentialId) { this.credentialId = credentialId; }

    public String getTenantId() { return tenantId; }
    public void setTenantId(String tenantId) { this.tenantId = tenantId; }

    public byte[] getPrivateKey() { return privateKey; }
    public void setPrivateKey(byte[] privateKey) { this.privateKey = privateKey; }

    public Json getPublicJwk() { return publicJwk; }
    public void setPublicJwk(Json publicJwk) { this.publicJwk = publicJwk; }

    public String getAlgorithm() { return algorithm; }
    public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }

    public String getFormat() { return format; }
    public void setFormat(String format) { this.format = format; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getRevokedAt() { return revokedAt; }
    public void setRevokedAt(Instant revokedAt) { this.revokedAt = revokedAt; }
}