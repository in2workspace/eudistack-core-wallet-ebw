package com.eudistack.ebw.domain.model.exception;

/**
 * Restricted onboarding mode: the email code is valid but the email has no account, and accounts
 * are only created with an onboarding ticket (FR-34). Nothing is created.
 */
public class NoAccountException extends RuntimeException {

    private final String signupUrl;

    /** @param signupUrl the tenant's onboarding address, {@code null} if it has none */
    public NoAccountException(String signupUrl) {
        super("The email has no account and the tenant only creates accounts with an onboarding ticket");
        this.signupUrl = signupUrl;
    }

    public String getSignupUrl() {
        return signupUrl;
    }
}
