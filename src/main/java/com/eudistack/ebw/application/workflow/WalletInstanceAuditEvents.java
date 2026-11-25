package com.eudistack.ebw.application.workflow;

/**
 * Audit events of the Wallet Instances (EUD-15 prd §3.8, design §3). Recorded in {@code audit_log} with
 * {@code entity_type = 'wallet_instance'} and the instance id, never the email of the account (FR-20).
 */
public final class WalletInstanceAuditEvents {

    public static final String ENTITY_WALLET_INSTANCE = "wallet_instance";

    public static final String WALLET_INSTANCE_REGISTERED = "WALLET_INSTANCE_REGISTERED";
    public static final String WALLET_INSTANCE_NOTICE_SENT = "WALLET_INSTANCE_NOTICE_SENT";
    public static final String WALLET_INSTANCE_NOTICE_FAILED = "WALLET_INSTANCE_NOTICE_FAILED";
    public static final String WALLET_INSTANCE_BOUND = "WALLET_INSTANCE_BOUND";
    public static final String WALLET_INSTANCE_BIND_REJECTED = "WALLET_INSTANCE_BIND_REJECTED";
    public static final String WALLET_INSTANCE_RENAMED = "WALLET_INSTANCE_RENAMED";
    public static final String WALLET_INSTANCE_REVOKED = "WALLET_INSTANCE_REVOKED";

    private WalletInstanceAuditEvents() {}
}
