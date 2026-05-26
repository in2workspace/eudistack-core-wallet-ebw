package com.eudistack.ebw.keymanager.domain.exception;

/**
 * Thrown when the tenant's wallet profile does not permit holder key generation.
 *
 * <p>The message is intentionally opaque: it names the tenant but gives no detail about WHY
 * the profile is unsupported, defending against capability-probing by malicious callers.
 * The HTTP layer maps this to a 403 with no response body (ES-02).</p>
 *
 * <p>Spec: EUDISTACK-119 ES-02.</p>
 */
public class TenantWalletProfileUnsupportedException extends RuntimeException {

    public TenantWalletProfileUnsupportedException(String tenantId) {
        super("Wallet profile not supported for tenant: " + tenantId);
    }
}