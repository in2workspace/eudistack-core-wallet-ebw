package com.eudistack.ebw.application.workflow;

/**
 * Audit events of registration and access (FR-22, prd §3.7). Recorded in {@code audit_log}
 * with the account, the passkey id and the rejection reason, never the email, the code, the
 * challenge or the authenticator response.
 */
public final class AuthAuditEvents {

    public static final String EMAIL_CODE_REQUESTED = "EMAIL_CODE_REQUESTED";
    public static final String EMAIL_CODE_VERIFIED = "EMAIL_CODE_VERIFIED";
    public static final String EMAIL_CODE_REJECTED = "EMAIL_CODE_REJECTED";
    public static final String ACCOUNT_CREATED = "ACCOUNT_CREATED";
    public static final String ACCOUNT_RECOGNIZED = "ACCOUNT_RECOGNIZED";
    public static final String PASSKEY_REGISTERED = "PASSKEY_REGISTERED";
    public static final String PASSKEY_REJECTED = "PASSKEY_REJECTED";
    public static final String NEW_PASSKEY_NOTICE_SENT = "NEW_PASSKEY_NOTICE_SENT";
    public static final String NEW_PASSKEY_NOTICE_FAILED = "NEW_PASSKEY_NOTICE_FAILED";
    public static final String ACCESS_GRANTED = "ACCESS_GRANTED";
    public static final String ACCESS_REJECTED = "ACCESS_REJECTED";
    public static final String SESSION_EXPIRED = "SESSION_EXPIRED";
    public static final String SESSION_ENDED = "SESSION_ENDED";
    public static final String OTHER_SESSIONS_ENDED = "OTHER_SESSIONS_ENDED";

    static final String ENTITY_EMAIL_VERIFICATION = "email_verification";
    static final String ENTITY_USER = "user";
    static final String ENTITY_PASSKEY = "passkey";
    static final String ENTITY_SESSION = "session";
    static final String ENTITY_CEREMONY = "webauthn_ceremony";

    private AuthAuditEvents() {}
}
