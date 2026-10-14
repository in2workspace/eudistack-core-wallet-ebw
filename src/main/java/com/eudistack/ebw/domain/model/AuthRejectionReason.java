package com.eudistack.ebw.domain.model;

import java.util.Locale;

/**
 * Fixed reason of a rejected passkey registration or sign-in, recorded in the audit trail and the
 * logs. The concrete WebAuthn library message only goes to DEBUG logs.
 */
public enum AuthRejectionReason {
    CEREMONY_MISSING,
    CEREMONY_INVALID,
    CEREMONY_MISMATCH,
    MALFORMED_RESPONSE,
    VERIFICATION_FAILED,
    CREDENTIAL_ALREADY_REGISTERED,
    PRF_UNSUPPORTED,
    UNKNOWN_CREDENTIAL,
    ACCOUNT_NOT_FOUND,
    TICKET_ACCOUNT_MISMATCH,
    USER_HANDLE_MISMATCH,
    SIGN_COUNT_NOT_ADVANCED;

    /** Lower-case code stored in the audit {@code reason}. */
    public String code() {
        return name().toLowerCase(Locale.ROOT);
    }
}
