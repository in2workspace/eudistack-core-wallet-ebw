package com.eudistack.ebw.domain.model.exception;

/** An account with the same email was created concurrently in the tenant. */
public class DuplicateAccountException extends RuntimeException {

    public DuplicateAccountException() {
        super("Account already exists");
    }
}
