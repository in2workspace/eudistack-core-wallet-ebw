package com.eudistack.ebw.domain.model.exception;

/**
 * Thrown when a REQUIRED tenant_config entry is missing for the current tenant.
 * Other tenants stay operational — only the requesting tenant fails fast.
 */
public class TenantConfigMissingException extends RuntimeException {

    public TenantConfigMissingException(String tenant, String key) {
        super("Missing required tenant_config key '" + key + "' for tenant '" + tenant
                + "'. Run seed-tenants[.stg].sql or populate via config API.");
    }
}
