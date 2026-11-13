package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.infrastructure.controller.support.AuthProblems;
import org.springframework.http.HttpStatus;

/**
 * A system token that is not accepted: 401 {@code invalid_token} (missing, malformed, expired,
 * not issued by the tenant's Verifier or of another tenant) or 403 {@code insufficient_permission}
 * (not a LEARCredentialMachine or without the tenant administrator power). The reason only goes
 * to the logs.
 */
public class SystemTokenRejectedException extends RuntimeException {

    private final HttpStatus status;
    private final String type;
    private final String reason;

    private SystemTokenRejectedException(HttpStatus status, String type, String reason) {
        super("System token rejected: " + reason);
        this.status = status;
        this.type = type;
        this.reason = reason;
    }

    public static SystemTokenRejectedException invalidToken(String reason) {
        return new SystemTokenRejectedException(HttpStatus.UNAUTHORIZED, AuthProblems.INVALID_TOKEN, reason);
    }

    public static SystemTokenRejectedException insufficientPermission(String reason) {
        return new SystemTokenRejectedException(HttpStatus.FORBIDDEN, AuthProblems.INSUFFICIENT_PERMISSION, reason);
    }

    public HttpStatus getStatus() { return status; }
    public String getType() { return type; }
    public String getReason() { return reason; }
}
