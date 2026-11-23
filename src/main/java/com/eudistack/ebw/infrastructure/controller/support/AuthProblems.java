package com.eudistack.ebw.infrastructure.controller.support;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;

import java.net.URI;

/**
 * RFC 9457 problems of the registration and access API, with the contract error code in
 * {@code type} (annex/openapi.yaml of EUD-8).
 */
public final class AuthProblems {

    public static final String INVALID_REQUEST = "invalid_request";
    public static final String INVALID_CODE = "invalid_code";
    public static final String EXPIRED_CODE = "expired_code";
    public static final String TOO_MANY_ATTEMPTS = "too_many_attempts";
    public static final String RATE_LIMITED = "rate_limited";
    public static final String INVALID_TICKET = "invalid_ticket";
    public static final String REGISTRATION_FAILED = "registration_failed";
    public static final String PASSKEY_PRF_UNSUPPORTED = "passkey_prf_unsupported";
    public static final String UNKNOWN_CREDENTIAL = "unknown_credential";
    public static final String AUTHENTICATION_FAILED = "authentication_failed";
    public static final String INVALID_SESSION = "invalid_session";
    /** System token, or "it was not me" token, not accepted (EUD-315). */
    public static final String INVALID_TOKEN = "invalid_token";
    public static final String INSUFFICIENT_PERMISSION = "insufficient_permission";
    public static final String ONBOARDING_DISABLED = "onboarding_disabled";
    /** Restricted onboarding mode, email without account (EUD-315). Carries {@code signupUrl}. */
    public static final String NO_ACCOUNT = "no_account";
    /** Not in the contract: the Verifier keys cannot be read, so no system token can be checked (EUD-315). */
    public static final String SERVICE_UNAVAILABLE = "service_unavailable";
    // Wallet Instances (EUD-15 annex/openapi.yaml)
    /** The session is not bound to an active Wallet Instance (403, AD-3). */
    public static final String INSTANCE_REQUIRED = "instance_required";
    /** No instance with that identifier in the account, also when it belongs to another account (404). */
    public static final String INSTANCE_NOT_FOUND = "instance_not_found";
    /** The instance is revoked: the Wallet App forgets it and registers a new one (410). */
    public static final String INSTANCE_REVOKED = "instance_revoked";
    /** More than 20 instance registrations per account and hour (429). */
    public static final String TOO_MANY_REQUESTS = "too_many_requests";
    /** Not in the contract: cookie endpoint called without {@code X-Wallet-Request: 1}. */
    public static final String FORBIDDEN = "forbidden";
    /** Not in the contract: server failure, for instance a tenant without {@code ebw.webauthn.rp_id}. */
    public static final String SERVER_ERROR = "server_error";

    private AuthProblems() {}

    public static ProblemDetail of(HttpStatus status, String type) {
        var problem = ProblemDetail.forStatus(status);
        problem.setType(URI.create(type));
        return problem;
    }
}
