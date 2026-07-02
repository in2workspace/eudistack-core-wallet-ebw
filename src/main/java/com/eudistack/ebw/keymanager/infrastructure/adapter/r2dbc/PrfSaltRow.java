package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc;

import java.time.Instant;
import java.util.UUID;

/**
 * R2DBC row-mapping POJO for the {@code hybrid_prf_salt} table.
 *
 * <p>Used exclusively by {@link PrfSaltRepository} raw-SQL mappings via
 * {@code DatabaseClient}. Spring Data's {@code ReactiveCrudRepository} is not used
 * because the table has a composite primary key ({@code holder_id, credential_id}),
 * which Spring Data R2DBC does not support natively (AD-4, technical-design.md §3.2).</p>
 *
 * <p>The {@code prf_salt} column maps directly to {@code byte[]} without any
 * base64/hex transformation — the BYTEA codec reads and writes raw bytes (EC-04,
 * EUDISTACK-537 AC-01).</p>
 *
 * <p>Spec: EUDISTACK-537 T2; architecture.md §5.3.</p>
 */
public class PrfSaltRow {

    private UUID holderId;
    private String credentialId;
    private byte[] prfSalt;
    private Instant createdAt;

    public UUID getHolderId() { return holderId; }
    public void setHolderId(UUID holderId) { this.holderId = holderId; }

    public String getCredentialId() { return credentialId; }
    public void setCredentialId(String credentialId) { this.credentialId = credentialId; }

    public byte[] getPrfSalt() { return prfSalt; }
    public void setPrfSalt(byte[] prfSalt) { this.prfSalt = prfSalt; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
